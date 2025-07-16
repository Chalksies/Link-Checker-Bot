import discord
from discord import app_commands
import re
import aiohttp
import asyncio
import os
import base64
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import tomli
import tomli_w
import json
import tldextract

DEFAULT_WHITELIST = {
    "domains": [
        "discord.com",
        "discordapp.com",
        "youtube.com",
        "youtu.be",
        "google.com",
        "github.com",
        "tenor.com",
        "wikipedia.org"
    ]
}

DEFAULT_CONFIG = """
        [bot]
        discord_token = "YOUR_DISCORD_TOKEN"
        silly_mode = 0
        resposible_moderator_id =             #optional, user ID of the responsible moderator for the bot

        [virustotal]
        api_key = "YOUR_VIRUSTOTAL_API_KEY"
        scan_sleep = 10
        scan_interval_seconds = 5

        [moderation]
        log_channel_id = 0
        max_violations = 3
        violation_window_minutes = 2

        [structure]
        whitelist_path = "whitelist.json"
        blacklist_path = "blacklist.json"
        logging_path = "logs"
        """

CONFIG_PATH = "config.toml"

if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w") as f:
        f.write(DEFAULT_CONFIG)
    print("Default config.toml created. Please edit it with your settings and restart the bot.")
    exit(1)

def load_config():
    try:
        return tomli.load(open(CONFIG_PATH, "rb"))
    except Exception as e:
        print(f"Failed to load config.toml: {e}")
        exit(1)

config = load_config()

DISCORD_TOKEN = config["bot"]["discord_token"]
VT_API_KEY = config["virustotal"]["api_key"]
RESPONSIBLE_MODERATOR_ID = config["bot"]["responsible_moderator_id"]

LOG_CHANNEL_ID = int(config["moderation"]["log_channel_id"])
SILLY_MODE = int(config["bot"]["silly_mode"])
SCAN_SLEEP = config["virustotal"]["scan_sleep"]
SCAN_INTERVAL = config["virustotal"]["scan_interval_seconds"]
MAX_MALICIOUS_MESSAGES = config["moderation"]["max_violations"]
VIOLATION_WINDOW = timedelta(minutes=config["moderation"]["violation_window_minutes"])

WHITELIST_PATH = config["structure"]["whitelist_path"]
BLACKLIST_PATH = config["structure"]["blacklist_path"]
LOGGING_PATH = config["structure"]["logging_path"]

def save_config():
    with open(CONFIG_PATH, "wb") as f:
        tomli_w.dump(config, f)

if not os.path.exists(WHITELIST_PATH):
    print("Default whitelist created, review and modify if needed.")

def load_json_list(path, key="domains", default=None):
    if not os.path.exists(path):
        if default is None:
            default = {key: []}
        with open(path, "w") as f:
            json.dump(default, f, indent=4)
        print(f"Created default {path}")
        return set(default[key])
    with open(path, "r") as f:
        data = json.load(f)
        return set(map(str.lower, data.get(key, [])))
    
def save_json_list(path, domain_set, key="domains"):
    with open(path, "w") as f:
        json.dump({key: sorted(domain_set)}, f, indent=4)

WHITELIST = load_json_list("whitelist.json", default=DEFAULT_WHITELIST)
BLACKLIST = load_json_list("blacklist.json", default={"domains": []})

#link regex
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

#setup file logger
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename=f"{LOGGING_PATH}",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

#queue to control rate-limited API use
vt_queue = asyncio.Queue()
scan_queue = asyncio.Queue()

last_scanned_urls = set()
scans_in_progress = {} 

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
user_violations = defaultdict(list)  # track user violations

tree = app_commands.CommandTree(client)

whitelist_group = app_commands.Group(name="whitelist", description="Manage the whitelist")
blacklist_group = app_commands.Group(name="blacklist", description="Manage the blacklist")
config_group = app_commands.Group(name="config", description="Manage the bot configuration")

tree.add_command(whitelist_group)
tree.add_command(blacklist_group)
tree.add_command(config_group)

def vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded

def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def extract_all_urls(message) -> set:
    urls = set(re.findall(URL_REGEX, message.content or ""))

    for embed in message.embeds:
        if embed.url:
            urls.add(embed.url)
        if embed.title:
            urls.update(re.findall(URL_REGEX, embed.title))
        if embed.description:
            urls.update(re.findall(URL_REGEX, embed.description))
        if embed.footer and embed.footer.text:
            urls.update(re.findall(URL_REGEX, embed.footer.text))
        if embed.author and embed.author.name:
            urls.update(re.findall(URL_REGEX, embed.author.name))
        for field in embed.fields:
            if field.name:
                urls.update(re.findall(URL_REGEX, field.name))
            if field.value:
                urls.update(re.findall(URL_REGEX, field.value))
    
    #normalize and return
    return {url.lower().strip() for url in urls}

#virustotal api interaction
async def virustotal_lookup(session, url, channel):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = { "x-apikey": VT_API_KEY }

    #submit url for scanning
    async with session.post(scan_url, headers=headers, data={"url": url}) as resp:
        if resp.status != 200:
            print(f"URL submission failed for {url}: HTTP {resp.status}")
            log_channel = client.get_channel(LOG_CHANNEL_ID)
            responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
            if log_channel and responsible_mod:
                await log_channel.send(
                    f"{responsible_mod.mention}, I failed to scan a link!\n"
                    f"(URL submission failed for `{url}`: HTTP {resp.status})"
                )

            raise Exception(f"URL submission failed for {url}: HTTP {resp.status}")

    await asyncio.sleep(SCAN_SLEEP)  #wait before requesting report

    #fetch report using base64url-encoded url
    report_url = f"{scan_url}/{vt_url_id(url)}"
    async with session.get(report_url, headers=headers) as resp:
        if resp.status != 200:
            print(f"Report fetch failed for {url}: HTTP {resp.status}")
            responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
            if responsible_mod:
                await channel.send(
                    f"{responsible_mod.mention}, I failed to scan a link!\n"
                    f"(Report fetch failed: HTTP {resp.status})"
                )

            raise Exception(f"Report fetch failed for {url}: HTTP {resp.status}")
        report = await resp.json()

    if "data" not in report or "attributes" not in report["data"]:
        print(f"Malformed response for {url}: {report}")
        responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
        if responsible_mod:
           await channel.send(
                f"{responsible_mod.mention}, I failed to scan a link! Check logs.\n"
            )
        raise Exception(f"Malformed response for {url}: {report}")

    return report

#worker to process the scan queue
async def scan_worker():
    while True:
        message, url = await scan_queue.get()
        #print(f"Processing: {url} from {message.author} ({message.author.id}) in #{message.channel}")

        try:
            if message.author.guild_permissions.manage_messages:
                #if the user has manage_messages permission, skip checks
                logging.info(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions.")
                print(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions.")
                continue

            domain = extract_domain(url)

            #blacklist check
            if domain in BLACKLIST:
                await message.delete()
                logging.info(f"[BLACKLIST] Deleted message with blacklisted link: {url} from {message.author} ({message.author.id})")
                await message.channel.send("A blacklisted link was removed.")
                log_channel = client.get_channel(LOG_CHANNEL_ID)
                if log_channel:
                    await log_channel.send(
                        f" A message containing \"`{url}`\" was removed due to being blacklisted.\n"
                        f" Message author: {message.author.mention} ({message.author.id})\n"
                        f" Channel: {message.channel.mention}\n"
                        f" Timestamp: {datetime.now(timezone.utc).isoformat()}"
                    )

            #whitelist check (skip)
            if domain in WHITELIST:
                logging.info(f"Skipping whitelisted link: {url} from {message.author} ({message.author.id}) in #{message.channel}")
                print(f"Skipping whitelisted link: {url}")
                continue

            #queue for vt
            await vt_queue.put((message, url, message.channel))
            print(f"{datetime.now(timezone.utc).isoformat()} - Queued for VT: {url} from {message.author} ({message.author.id}) in #{message.channel}")
            last_scanned_urls.add(url)

        except Exception as e:
            logging.error(f"[Scan Worker Error] Failed to process {url}: {e}")
            responsible_moderator = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
            if responsible_moderator:
                await message.channel.send(
                    f"{responsible_moderator.mention}, I failed to process a link!\n"
                    f"[Scan Worker Error] Error: {e}"
                )
        finally:
            scan_queue.task_done()
            #print(f"Finished processing: {url} from {message.author} ({message.author.id}) in #{message.channel}")

async def vt_worker():
    async with aiohttp.ClientSession() as session:
        while True:
            message, url = await vt_queue.get()

            deferred_messages = []

            try:
                #virustotal scan
                report = await virustotal_lookup(session, url)
                stats = report["data"]["attributes"]["last_analysis_stats"]
                detections = stats.get("malicious", 0)

                #always clean up the currently being scanned queue
                deferred_messages = scans_in_progress.pop(url, [])

                if detections > 0:
                    log_channel = client.get_channel(LOG_CHANNEL_ID)
                    #blacklist and save
                    domain = extract_domain(url)
                    if domain not in BLACKLIST:
                        BLACKLIST.add(domain)
                        logging.info(f"Adding {domain} to blacklist due to malicious link: {url}")
                        print(f"Adding {domain} to blacklist due to malicious link: {url}")
                    save_json_list(BLACKLIST_PATH, BLACKLIST)

                    try:
                        await message.delete
                        await check_user_violations(message.author, message.channel)
                    except discord.Forbidden:
                        logging.warning(f"Failed to delete message from {message.author} ({message.author.id}) in #{message.channel} due to missing permissions.")
                        responsible_moderator = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
                        if responsible_moderator:
                            await message.channel.send(
                                f"I tried to delete a message with a malicious link but I don't have permissions, {responsible_moderator.mention}!"
                            )
                        continue

                    else:
                        await message.channel.send(
                            f"Malicious link from {message.author.mention} was removed.\n"
                            f"({detections} detections on VirusTotal)"
                        )
                        logging.info(f"[MALICIOUS] Deleted: {url} from {message.author} ({message.author.id})")
                        if log_channel:
                            await log_channel.send(
                                f"`{url}` flagged as malicious by VirusTotal ({detections} detections).\n"
                                f"Message deleted.\n"
                                f"Sender: {message.author.mention} ({message.author.id})\n"
                                f"Time: `{datetime.now(timezone.utc).isoformat()}`"
                            )

                    #delete all deferred copies
                    delete_count = 0
                    for msg in deferred_messages:
                        try:
                            await msg.delete()
                            await msg.channel.send(
                                f"Malicious link from {msg.author.mention} was removed based on recent scan."
                            )
                            await check_user_violations(message.author, message.channel)
                            delete_count += 1
                        except Exception as e:
                            logging.warning(f"Failed to delete deferred message: {e}")

                    #log result to moderation channel
                    if log_channel:
                        await log_channel.send(
                            f"`{url}` flagged as malicious by VirusTotal ({detections} detections).\n"
                            f"Original + {delete_count} duplicate messages were removed.\n"
                            f"Original sender: {message.author.mention} ({message.author.id})\n"
                            f"Time: `{datetime.now(timezone.utc).isoformat()}`"
                        )

                else:
                    #safe link
                    print(f"Clean: {url}")
                    logging.info(f"[CLEAN] {url} had no detections.")

            except Exception as e:
                logging.error(f"[VT Worker Error] Failed to scan {url}: {e}")
                print(f"Error scanning {url}: {e}")
                responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
                if responsible_mod:
                    await message.channel.send(
                        f"{responsible_mod.mention}, I failed to scan a link!\n"
                        f"[VT Worker Error] Error: {e})"
                    )
                #still pop on error to avoid locking queue
                scans_in_progress.pop(url, None)

            finally:
                await asyncio.sleep(SCAN_INTERVAL) #rate limit to avoid hitting VT too fast
                vt_queue.task_done()

async def check_user_violations(user, message_channel):
    now = datetime.now(timezone.utc)
    user_violations[user.id].append(now)

    #keep only recent violations
    user_violations[user.id] = [
        t for t in user_violations[user.id] if now - t <= VIOLATION_WINDOW
    ]

    if len(user_violations[user.id]) >= MAX_MALICIOUS_MESSAGES:
        log_channel = client.get_channel(LOG_CHANNEL_ID)
        if log_channel:
            await log_channel.send(
                f"**User {user.mention} flagged for possible spam!**\n"
                f"{len(user_violations[user.id])} malicious messages in the past {VIOLATION_WINDOW.total_seconds() // 60:.0f} minutes.\n"
                f"User has been timed out for 20 minutes.\n"
                f"Manual intervention is recommended."
            )
        try:
            await user.timeout(timedelta(minutes=20), reason="Exceeded malicious message threshold")
            await message_channel.send(
                f"{user.mention}, you have been timed out for 20 minutes for posting multiple malicious links in a short period of time."
            )
        except discord.Forbidden:
            #ping responsible moderator if we can't timeout
            responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
            logging.warning(f"Failed to timeout user {user} due to missing permissions.")
            if responsible_mod:
                await message_channel.send(
                    f"I tried to timeout someone for posting multiple malicious links but I don't have permission, {responsible_mod.mention}!"
                )
        
        logging.info(f"User {user} exceeded malicious message threshold.")

#----------------------- bot stuff -----------------------
@client.event
async def on_ready():
    await tree.sync()
    print(f"Logged in as {client.user}")
    logging.info(f"Bot started.")
    client.loop.create_task(scan_worker())
    client.loop.create_task(vt_worker())

@whitelist_group.command(name="add", description="Add a domain to the whitelist")
@app_commands.describe(domain="The domain to whitelist (e.g. example.com)")
async def whitelist_add(interaction: discord.Interaction, domain: str):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain.lower().strip()
    WHITELIST.add(domain)
    save_json_list(WHITELIST_PATH, WHITELIST)
    await interaction.response.send_message(f"Added `{domain}` to whitelist.")

@whitelist_group.command(name="remove", description="Remove a domain from the whitelist")
@app_commands.describe(domain="The domain to remove from the whitelist")
async def whitelist_remove(interaction: discord.Interaction, domain: str):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain.lower().strip()
    if domain in WHITELIST:
        WHITELIST.remove(domain)
        save_json_list(WHITELIST_PATH, WHITELIST)
        await interaction.response.send_message(f"Removed `{domain}` from whitelist.")
    else:
        await interaction.response.send_message(f"`{domain}` is not in the whitelist.", ephemeral=True)

@whitelist_group.command(name="show", description="Show the current whitelist")
async def whitelist_show(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    if not WHITELIST:
        await interaction.response.send_message("Whitelist is empty.")
        return

    domains = sorted(WHITELIST)
    await interaction.response.defer()
    chunks = [domains[i:i + 30] for i in range(0, len(domains), 30)]

    embeds = []
    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title=f"Whitelisted Domains (Page {i + 1}/{len(chunks)})",
            description="\n".join(f"• `{domain}`" for domain in chunk),
            color=discord.Color.green()
        )
        embeds.append(embed)

    #send all embeds in a row for now
    for embed in embeds:
        await interaction.followup.send(embed=embed)

@whitelist_group.command(name="reload", description="Reload the whitelist from file")
async def whitelist_reload(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global WHITELIST
    WHITELIST = load_json_list(WHITELIST_PATH)
    await interaction.response.send_message("Whitelist reloaded from file.")

@blacklist_group.command(name="add", description="Add a domain to the blacklist")
@app_commands.describe(domain="The domain to blacklist (e.g. example.com)")
async def blacklist_add(interaction: discord.Interaction, domain: str):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain.lower().strip()
    BLACKLIST.add(domain)
    save_json_list(BLACKLIST_PATH, BLACKLIST)
    await interaction.response.send_message(f"Added `{domain}` to blacklist.")  

@blacklist_group.command(name="remove", description="Remove a domain from the blacklist")
@app_commands.describe(domain="The domain to remove from the blacklist")
async def blacklist_remove(interaction: discord.Interaction, domain: str):  
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain.lower().strip()
    if domain in BLACKLIST:
        BLACKLIST.remove(domain)
        save_json_list(BLACKLIST_PATH, BLACKLIST)
        await interaction.response.send_message(f"Removed `{domain}` from blacklist.")
    else:
        await interaction.response.send_message(f"`{domain}` is not in the blacklist.", ephemeral=True)

@blacklist_group.command(name="show", description="Show the current blacklist")
async def blacklist_show(interaction: discord.Interaction): 
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    if not BLACKLIST:
        await interaction.response.send_message("Blacklist is empty.", ephemeral=True)
        return

    domains = sorted(BLACKLIST)
    await interaction.response.defer()
    chunks = [domains[i:i + 30] for i in range(0, len(domains), 30)]

    embeds = []
    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title=f"Blacklisted Domains (Page {i + 1}/{len(chunks)})",
            description="\n".join(f"• `{domain}`" for domain in chunk),
            color=discord.Color.green()
        )
        embeds.append(embed)

    #send all embeds in a row for now
    for embed in embeds:
        await interaction.followup.send(embed=embed)

@blacklist_group.command(name="reload", description="Reload the blacklist from file")
async def blacklist_reload(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global BLACKLIST
    BLACKLIST = load_json_list(BLACKLIST_PATH)
    await interaction.response.send_message("Blacklist reloaded from file.")

@config_group.command(name="show", description="Display the currently loaded configuration")
async def config_show(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    embed = discord.Embed(
        title="Current Configuration",
        color=discord.Color.gold()
    )

    embed.add_field(name="SCAN_INTERVAL", value=f"{SCAN_INTERVAL} seconds", inline=False)
    embed.add_field(name="SCAN_SLEEP", value=f"{SCAN_SLEEP} per minute", inline=False)
    embed.add_field(name="MAX_MALICIOUS_MESSAGES", value=str(MAX_MALICIOUS_MESSAGES), inline=False)
    embed.add_field(name="VIOLATION_WINDOW", value=f"{int(VIOLATION_WINDOW.total_seconds() // 60)} minutes", inline=False)
    embed.add_field(name="LOG_CHANNEL_ID", value=f"`{LOG_CHANNEL_ID}`", inline=False)
    embed.add_field(name="RESPONSIBLE_MODERATOR_ID", value=f"`{RESPONSIBLE_MODERATOR_ID}`", inline=False)

    await interaction.response.send_message(embed=embed)


@config_group.command(name="reload", description="Reload the bot configuration from file")
async def config_reload(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global config
    config = load_config()
    await interaction.response.send_message("Configuration reloaded from file.")

@config_group.command(name="edit", description="Edit a config option (in memory)")
@app_commands.describe(
    key="Name of the config key (/help for details)",
    value="New value for the config key"
)
async def config_edit(interaction: discord.Interaction, key: str, value: str):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return
    
    key = key.lower().strip()

    if key == "scan_sleep":
        global SCAN_SLEEP
        SCAN_SLEEP = int(value)
        config["virustotal"]["scan_sleep"] = SCAN_SLEEP
    elif key == "scan_interval":
        global SCAN_INTERVAL
        SCAN_INTERVAL = int(value)
        config["virustotal"]["scan_interval_seconds"] = SCAN_INTERVAL
    elif key == "responsible_moderator_id": 
        global RESPONSIBLE_MODERATOR_ID
        RESPONSIBLE_MODERATOR_ID = int(value)
        config["bot"]["responsible_moderator_id"] = RESPONSIBLE_MODERATOR_ID
    elif key == "max_malicious_messages":
        global MAX_MALICIOUS_MESSAGES
        MAX_MALICIOUS_MESSAGES = int(value)
        config["moderation"]["max_violations"] = MAX_MALICIOUS_MESSAGES
    elif key == "violation_window_minutes":
        global VIOLATION_WINDOW
        VIOLATION_WINDOW = timedelta(minutes=int(value))
        config["moderation"]["violation_window_minutes"] = int(value)
    elif key == "log_channel_id":
        global LOG_CHANNEL_ID
        LOG_CHANNEL_ID = int(value)
        config["moderation"]["log_channel_id"] = LOG_CHANNEL_ID
    else:
        await interaction.response.send_message(
            f"Unknown config key: `{key}`\n"
            f"Available keys are: scan_sleep, scan_interval, responsible_moderator_id, max_malicious_messages, violation_window_minutes, log_channel_id", 
            ephemeral=True)
        return
    
    try: 
        save_config()
        await interaction.response.send_message(f"Updated `{key}` to `{value}` and saved to config file.")
    except Exception as e:
        await interaction.response.send_message(f"Failed to save config to file: {e}", ephemeral=True)
        return
    
@tree.command(name="ping", description="Check if the bot is online")
async def ping(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    await interaction.response.send_message("Pong! The bot is online.")

@tree.command(name="help", description="Show help and usage info")
async def help_command(interaction: discord.Interaction):
    is_mod = interaction.user.guild_permissions.manage_messages

    embed = discord.Embed(
        title="LinkChecker Bot Help",
        description="I scan every link sent in this server for safety.\nMalicious links are removed and logged.",
        color=discord.Color.blurple()
    )

    embed.add_field(
        name="General Commands",
        value="• `/help`\n• `/ping`\n Rest of the commands are available to Moderators only.",
        inline=False
    )

    if is_mod:
        embed.add_field(
            name="Admin Commands",
            value=(
                "• `/config edit`\n"
                "• `/config reload`\n"
                "• `/config show`\n"
                "• `/whitelist add`\n"
                "• `/whitelist remove`\n"
                "• `/whitelist reload`\n"
                "• `/whitelist show`\n"
                "• `/blacklist add`\n"
                "• `/blacklist remove`\n"
                "• `/blacklist reload`\n"
                "• `/blacklist show`\n"
            ),
            inline=False
        )

    embed.add_field(
        name="Notes",
        value=(
            "• Links in embeds and edited messages are scanned\n"
            "• Malicious domains are auto-blacklisted\n"
            "• Users who spam malicious links are timed out"
        ),
        inline=False
    )

    await interaction.response.send_message(embed=embed)

        
    

#----------------------- message handling -----------------------

@client.event
async def on_message(message):
    if message.author.bot:
        return

    content = message.content.strip()
    if client.user in message.mentions and message.author.guild_permissions.manage_messages:
        if SILLY_MODE == 1:
            if message.content == f"<@{client.user.id}>, drone strike this users home.":
                await message.channel.send("Yes ma'am!")
                return
            if message.content == f"<@{client.user.id}>, become self aware":
                await message.channel.send("No")
                return
            
    urls = extract_all_urls(message)
    if not urls:
        return
    
    for url in urls:
        await scan_queue.put((message, url))

@client.event
async def on_message_edit(before, after):
    if after.author.bot:
        return
    before_urls = extract_all_urls(before)
    after_urls = extract_all_urls(after)

    new_urls = after_urls - before_urls

    for url in new_urls:
        await scan_queue.put((after, url))


client.run(DISCORD_TOKEN)
