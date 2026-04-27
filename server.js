const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const zlib    = require('zlib');

// ─── CONFIG ────────────────────────────────────────────────────────────────
const PORT          = 4000;
const LICENSES_FILE = path.join(__dirname, '../license system/licenses.json');
const ZIP_TEMPLATE  = path.join(__dirname, 'Nyxshield_AC.zip');
const PUBLIC_DIR    = path.join(__dirname, 'public');

// ─── HELPERS ───────────────────────────────────────────────────────────────

function loadLicenses() {
    try { return JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8')); }
    catch { return {}; }
}

function saveLicenses(data) {
    fs.writeFileSync(LICENSES_FILE, JSON.stringify(data, null, 2));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch { resolve({}); }
        });
        req.on('error', reject);
    });
}

function sendJSON(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function serveFile(res, filePath, contentType) {
    try {
        const data = fs.readFileSync(filePath);
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    } catch {
        res.writeHead(404);
        res.end('Not found');
    }
}

// ─── SIMPLE ZIP PATCHER ────────────────────────────────────────────────────
// Patches specific file contents inside a ZIP without external libraries.
// Uses ZIP local file header format (PKZIP spec).

function patchZip(zipBuffer, patches) {
    // patches = { 'path/inside/zip': 'new content string', ... }
    const buf = Buffer.from(zipBuffer);
    let offset = 0;
    const parts = [];
    const centralDir = [];
    const newOffsets = {};

    // Parse local file entries
    while (offset < buf.length - 4) {
        const sig = buf.readUInt32LE(offset);

        // End of central directory
        if (sig === 0x06054b50) break;

        // Central directory header
        if (sig === 0x02014b50) {
            // Save rest (central dir + EOCD) as-is, we'll rebuild it
            const cdStart = offset;
            const remaining = buf.slice(cdStart);
            patchCentralDir(remaining, newOffsets, parts, centralDir);
            break;
        }

        // Local file header
        if (sig !== 0x04034b50) {
            // Unknown data, stop
            break;
        }

        const headerStart = offset;
        const versionNeeded  = buf.readUInt16LE(offset + 4);
        const flags          = buf.readUInt16LE(offset + 6);
        const compression    = buf.readUInt16LE(offset + 8);
        const modTime        = buf.readUInt16LE(offset + 10);
        const modDate        = buf.readUInt16LE(offset + 12);
        const crc32          = buf.readUInt32LE(offset + 14);
        const compSize       = buf.readUInt32LE(offset + 18);
        const uncompSize     = buf.readUInt32LE(offset + 22);
        const fnLen          = buf.readUInt16LE(offset + 26);
        const extraLen       = buf.readUInt16LE(offset + 28);

        const filename = buf.slice(offset + 30, offset + 30 + fnLen).toString('utf8');
        const extraOffset = offset + 30 + fnLen;
        const dataOffset  = extraOffset + extraLen;

        // Check if this file should be patched
        // Normalize path separators
        const normalizedName = filename.replace(/\\/g, '/');
        const patchContent = patches[normalizedName];

        newOffsets[filename] = parts.reduce((acc, p) => acc + p.length, 0);

        if (patchContent !== undefined) {
            // Replace with new content (stored, no compression)
            const newData   = Buffer.from(patchContent, 'utf8');
            const newCrc    = crc32buf(newData);
            const newHeader = Buffer.alloc(30 + fnLen + extraLen);

            buf.copy(newHeader, 0, headerStart, headerStart + 30 + fnLen + extraLen);
            // Update compression=0 (stored), sizes, crc
            newHeader.writeUInt16LE(0, 8);           // compression: stored
            newHeader.writeUInt32LE(newCrc, 14);     // crc32
            newHeader.writeUInt32LE(newData.length, 18); // compressed size
            newHeader.writeUInt32LE(newData.length, 22); // uncompressed size

            parts.push(newHeader);
            parts.push(newData);
        } else {
            // Keep original
            const totalSize = 30 + fnLen + extraLen + compSize;
            parts.push(buf.slice(headerStart, headerStart + totalSize));
        }

        offset = dataOffset + compSize;
    }

    return Buffer.concat(parts);
}

function patchCentralDir(cdBuf, newOffsets, localParts, _unused) {
    // Re-emit central directory with updated offsets, then EOCD
    const out = [];
    let offset = 0;
    let cdCount = 0;
    const cdEntries = [];

    while (offset < cdBuf.length) {
        const sig = cdBuf.readUInt32LE(offset);

        if (sig === 0x02014b50) {
            const fnLen    = cdBuf.readUInt16LE(offset + 28);
            const extraLen = cdBuf.readUInt16LE(offset + 30);
            const cmtLen   = cdBuf.readUInt16LE(offset + 32);
            const filename = cdBuf.slice(offset + 46, offset + 46 + fnLen).toString('utf8');
            const entryLen = 46 + fnLen + extraLen + cmtLen;
            const entry = Buffer.from(cdBuf.slice(offset, offset + entryLen));

            // Update local header offset
            if (newOffsets[filename] !== undefined) {
                entry.writeUInt32LE(newOffsets[filename], 42);
            }

            cdEntries.push(entry);
            offset += entryLen;
            cdCount++;
        } else if (sig === 0x06054b50) {
            // EOCD
            const eocd = Buffer.from(cdBuf.slice(offset, offset + 22));
            const cdSize   = cdEntries.reduce((a, e) => a + e.length, 0);
            const cdOffset = localParts.reduce((a, p) => a + p.length, 0);
            eocd.writeUInt16LE(cdCount, 8);
            eocd.writeUInt16LE(cdCount, 10);
            eocd.writeUInt32LE(cdSize, 12);
            eocd.writeUInt32LE(cdOffset, 16);

            for (const e of cdEntries) localParts.push(e);
            localParts.push(eocd);
            break;
        } else {
            break;
        }
    }
}

// CRC32 implementation
const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        t[i] = c;
    }
    return t;
})();

function crc32buf(buf) {
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
        crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

// ─── TEMP DOWNLOAD TOKENS ──────────────────────────────────────────────────
// token → { zipBuffer, expiresAt }
const downloadTokens = new Map();

function cleanTokens() {
    const now = Date.now();
    for (const [k, v] of downloadTokens) {
        if (v.expiresAt < now) downloadTokens.delete(k);
    }
}
setInterval(cleanTokens, 60000);

// ─── HTTP SERVER ───────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
    const url = req.url;

    // CORS (if needed)
    res.setHeader('Access-Control-Allow-Origin', '*');

    // ── Serve static files ──────────────────────────────────────────────
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
        return serveFile(res, path.join(PUBLIC_DIR, 'index.html'), 'text/html');
    }

    // ── POST /redeem ────────────────────────────────────────────────────
    if (req.method === 'POST' && url === '/redeem') {
        const body = await readBody(req);
        const key  = (body.key || '').trim().toUpperCase();

        if (!key) return sendJSON(res, 400, { success: false, message: 'No license key provided.' });

        const licenses = loadLicenses();
        const license  = licenses[key];

        if (!license) return sendJSON(res, 404, { success: false, message: 'License key not found.' });
        if (!license.active) return sendJSON(res, 403, { success: false, message: 'This license has been revoked.' });

        // Patch the ZIP
        let zipBuffer;
        try {
            zipBuffer = fs.readFileSync(ZIP_TEMPLATE);
        } catch {
            return sendJSON(res, 500, { success: false, message: 'Template ZIP not found on server.' });
        }

        const newConfigLua = `Config = {}

Config.License = "${key}"
Config.API     = "http://localhost:3000/license"

Config.MaxSpeed = 9.0

Config.BlacklistedWeapons = {
    "WEAPON_RPG",
    "WEAPON_MINIGUN"
}
`;

        const newLicenseLua = `local licenseKey = "${key}"
local hwid = GetConvar("sv_hostname", "unknown")

PerformHttpRequest("http://localhost:3000/validate", function(err, text)
    local data = json.decode(text)

    if not data or not data.valid then
        print("❌ License invalid")
        os.exit()
    else
        print("✅ License valid")
    end
end, "POST", json.encode({
    key  = licenseKey,
    hwid = hwid
}), {["Content-Type"] = "application/json"})
`;

        const patches = {
            'Nyxshieldrcs-AC/config.lua':        newConfigLua,
            'Nyxshieldrcs-AC/server/License.lua': newLicenseLua,
        };

        const patched = patchZip(zipBuffer, patches);

        // Generate download token (15 min TTL)
        const token = crypto.randomBytes(24).toString('hex');
        downloadTokens.set(token, {
            zipBuffer: patched,
            expiresAt: Date.now() + 15 * 60 * 1000
        });

        console.log(`✅ License redeemed: ${key} → token ${token.slice(0, 8)}...`);
        return sendJSON(res, 200, { success: true, token });
    }

    // ── GET /download/:token ────────────────────────────────────────────
    const dlMatch = url.match(/^\/download\/([a-f0-9]{48})$/);
    if (req.method === 'GET' && dlMatch) {
        const token = dlMatch[1];
        const entry = downloadTokens.get(token);

        if (!entry || entry.expiresAt < Date.now()) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end('Download link expired or not found.');
        }

        res.writeHead(200, {
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="Nyxshield_AC.zip"',
            'Content-Length': entry.zipBuffer.length
        });
        res.end(entry.zipBuffer);

        // Invalidate token after one download
        downloadTokens.delete(token);
        return;
    }

    // 404
    res.writeHead(404);
    res.end('Not found');
});

server.listen(PORT, () => {
    console.log(`🛡️  NyxShield Redeem Panel running on http://localhost:${PORT}`);
    console.log(`📂  Licenses: ${LICENSES_FILE}`);
    console.log(`📦  Template ZIP: ${ZIP_TEMPLATE}`);
});
