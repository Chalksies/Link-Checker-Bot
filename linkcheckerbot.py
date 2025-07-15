import discord
import re
import aiohttp
import asyncio
import os
import base64
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import tomli
import json

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
        scan_interval_seconds = 10

        [moderation]
        log_channel_id = 0
        max_violations = 3
        violation_window_minutes = 2

        [structure]
        whitelist_path = "whitelist.json"
        blacklist_path = "blacklist.json"
        logging_path = "logs"
        """

if not os.path.exists("config.toml"):
    with open("config.toml", "w") as f:
        f.write(DEFAULT_CONFIG)
    print("Default config.toml created. Please edit it with your settings and restart the bot.")
    exit(1)

config = tomli.load(open("config.toml", "rb"))

DISCORD_TOKEN = config["bot"]["discord_token"]
VT_API_KEY = config["virustotal"]["api_key"]
RESPONSIBLE_MODERATOR_ID = config["bot"]["responsible_moderator_id"]

LOG_CHANNEL_ID = int(config["moderation"]["log_channel_id"])
SILLY_MODE = int(config["bot"]["silly_mode"])
SCAN_INTERVAL = config["virustotal"]["scan_interval_seconds"]
MAX_MALICIOUS_MESSAGES = config["moderation"]["max_violations"]
VIOLATION_WINDOW = timedelta(minutes=config["moderation"]["violation_window_minutes"])

WHITELIST_PATH = config["structure"]["whitelist_path"]
BLACKLIST_PATH = config["structure"]["blacklist_path"]
LOGGING_PATH = config["structure"]["logging_path"]

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

def vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded

#virustotal api interaction
async def virustotal_lookup(session, url):
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

    await asyncio.sleep(SCAN_INTERVAL)  #wait before requesting report

    #fetch report using base64url-encoded url
    report_url = f"{scan_url}/{vt_url_id(url)}"
    async with session.get(report_url, headers=headers) as resp:
        if resp.status != 200:
            print(f"Report fetch failed for {url}: HTTP {resp.status}")
            log_channel = client.get_channel(LOG_CHANNEL_ID)
            responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
            if log_channel and responsible_mod:
                await log_channel.send(
                    f"{responsible_mod.mention}, I failed to scan a link!\n"
                    f"(Report fetch failed for `{url}`: HTTP {resp.status})"
                )

            raise Exception(f"Report fetch failed for {url}: HTTP {resp.status}")
        report = await resp.json()

    if "data" not in report or "attributes" not in report["data"]:
        print(f"Malformed response for {url}: {report}")
        log_channel = client.get_channel(LOG_CHANNEL_ID)
        responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
        if log_channel and responsible_mod:
            await log_channel.send(
                f"{responsible_mod.mention}, I failed to scan a link!\n"
                f"(Malformed response for `{url}`: {report})"
            )
        raise Exception(f"Malformed response for {url}: {report}")

    return report

#worker to process the scan queue
async def scan_worker():
    while True:
        message, url, is_attempting_bypass = await scan_queue.get()
        norm_url = url.lower().strip()
        #print(f"Processing: {url} from {message.author} ({message.author.id}) in #{message.channel}")

        try:
            if message.author.guild_permissions.manage_messages:
                #if the user has manage_messages permission, skip checks
                logging.info(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions.")
                print(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions.")
                continue

            #blacklist check
            if any(blacklisted in norm_url for blacklisted in BLACKLIST):
                await message.delete()
                logging.info(f"[BLACKLIST] Deleted message with blacklisted link: {norm_url} from {message.author} ({message.author.id})")
                await message.channel.send("A blacklisted link was removed.")
                log_channel = client.get_channel(LOG_CHANNEL_ID)
                if log_channel:
                    await log_channel.send(
                        f" A message containing \"`{url}`\" was removed due to being blacklisted.\n"
                        f" Message author: {message.author.mention} ({message.author.id})\n"
                        f" Channel: {message.channel.mention}\n"
                        f" Timestamp: {datetime.now(timezone.utc).isoformat()}"
                    )
                if is_attempting_bypass:
                    await message.channel.send(
                        f"{message.author.mention}, you attempted to bypass the link checker logic by disguising it as a command. This incident will be reported."
                    )
                    if log_channel:
                        await log_channel.send(
                            f"User {message.author.mention} ({message.author.id}) attempted to **bypass** the link checker by disguising it as a command!\n"
                            f"Blocked Link: `{url}` (Blacklist)\n"
                            f"Channel: {message.channel.mention}\n"
                            f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
                        )
                continue

            #whitelist check (skip)
            if any(whitelisted in norm_url for whitelisted in WHITELIST):
                logging.info(f"Skipping whitelisted link: {norm_url} from {message.author} ({message.author.id}) in #{message.channel}")
                print(f"Skipping whitelisted link: {norm_url}")
                continue

            #queue for vt
            await vt_queue.put((message, norm_url, is_attempting_bypass))
            print(f"{datetime.now(timezone.utc).isoformat()} - Queued for VT: {norm_url} from {message.author} ({message.author.id}) in #{message.channel}")
            last_scanned_urls.add(norm_url)

        except Exception as e:
            logging.error(f"[Scan Worker Error] Failed to process {url}: {e}")
        finally:
            scan_queue.task_done()
            #print(f"Finished processing: {url} from {message.author} ({message.author.id}) in #{message.channel}")

async def vt_worker():
    async with aiohttp.ClientSession() as session:
        while True:
            message, url, is_attempting_bypass = await vt_queue.get()
            norm_url = url.lower().strip()

            deferred_messages = []

            try:
                #virustotal scan
                report = await virustotal_lookup(session, url)
                stats = report["data"]["attributes"]["last_analysis_stats"]
                detections = stats.get("malicious", 0)

                #always clean up the currently being scanned queue
                deferred_messages = scans_in_progress.pop(norm_url, [])

                if detections > 0:
                    log_channel = client.get_channel(LOG_CHANNEL_ID)
                    #blacklist and save
                    BLACKLIST.add(norm_url)
                    save_json_list(BLACKLIST_PATH, BLACKLIST)

                    try:
                        await message.delete
                        await check_user_violations(message.author, message.channel)
                    except discord.Forbidden:
                        logging.warning(f"Failed to delete message from {message.author} ({message.author.id}) in #{message.channel} due to missing permissions.")
                        await message.channel.send(
                            f"I tried to delete a message with a malicious link, but I don't have permissions!"
                        )
                        continue

                    if is_attempting_bypass:
                        await message.channel.send(
                            f"{message.author.mention}, you attempted to bypass the link checker logic by disguising it as a command. This incident will be reported."
                        )
                        if log_channel:
                            await log_channel.send(
                                f"User {message.author.mention} ({message.author.id}) attempted to **bypass** the link checker by disguising it as a command!\n"
                                f"Blocked Link: `{url}` (Malicious)\n"
                                f"Channel: {message.channel.mention}\n"
                                f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
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
                log_channel = client.get_channel(LOG_CHANNEL_ID)
                responsible_mod = await client.fetch_user(RESPONSIBLE_MODERATOR_ID)
                if log_channel and responsible_mod:
                    await log_channel.send(
                        f"{responsible_mod.mention}, I failed to scan a link!\n"
                        f"[VT Worker Error] Error scanning `{url}`: {e})"
                    )
                #still pop on error to avoid locking queue
                scans_in_progress.pop(norm_url, None)

            finally:
                await asyncio.sleep(SCAN_INTERVAL)
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
                f"Manual intervention is recommended."
            )
        logging.info(f"User {user} exceeded malicious message threshold.")




#----------------------- bot stuff -----------------------
@client.event
async def on_ready():
    print(f"Logged in as {client.user}")
    logging.info(f"Bot started at {datetime.now(timezone.utc).isoformat()}")
    client.loop.create_task(scan_worker())
    client.loop.create_task(vt_worker())

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

    #handle commands
    if content.startswith("lc!"):
        global BLACKLIST, WHITELIST
        #check permission
        if not message.author.guild_permissions.manage_messages:
            await message.channel.send("You don't have permission to configure the bot.")

            #check if the user is trying to bypass the link checker
            urls = re.findall(URL_REGEX, message.content)
            for url in urls:
                norm_url = url.lower().strip()
                if norm_url not in last_scanned_urls:
                    is_attempting_bypass = True
                    last_scanned_urls.add(norm_url)
                    await scan_queue.put((message, norm_url, is_attempting_bypass))
            return

        #command parsing
        if content.startswith("lc!whitelist add "):
            domain = content[len("lc!whitelist add "):].strip().lower()
            WHITELIST.add(domain)
            save_json_list(WHITELIST_PATH, WHITELIST)
            await message.channel.send(f"Added `{domain}` to whitelist.")
            logging.info(f"Added `{domain}` to whitelist by {message.author} ({message.author.id})")
            return

        elif content.startswith("lc!whitelist remove "):
            domain = content[len("lc!whitelist remove "):].strip().lower()
            if domain in WHITELIST:
                WHITELIST.remove(domain)
                save_json_list(WHITELIST_PATH, WHITELIST)
                await message.channel.send(f"Removed `{domain}` from whitelist.")
                logging.info(f"Removed `{domain}` from whitelist by {message.author} ({message.author.id})")
            else:
                await message.channel.send(f"`{domain}` is not in the whitelist.")
            return

        elif content == "lc!whitelist show":
            if not WHITELIST:
                await message.channel.send("Whitelist is empty.")
            else:
                domains = sorted(WHITELIST)
                chunks = [domains[i:i+20] for i in range(0, len(domains), 30)]  # avoid message length errors
                for i, chunk in enumerate(chunks):
                    await message.channel.send(
                        f"**Whitelisted Domains** (page {i+1}/{len(chunks)}):\n" +
                        "\n".join(f"- `{domain}`" for domain in chunk)
                    )
            return

        elif content == "lc!reload whitelist" or content == "lc!whitelist reload":
            WHITELIST = load_json_list(WHITELIST_PATH)
            await message.channel.send("Whitelist reloaded from file.")
            logging.info("Whitelist reloaded from file.")
            return

        elif content.startswith("lc!blacklist add "):
            domain = content[len("lc!blacklist add "):].strip().lower()
            BLACKLIST.add(domain)
            save_json_list(BLACKLIST_PATH, BLACKLIST)
            await message.channel.send(f"Added `{domain}` to blacklist.")
            logging.info(f"Added `{domain}` to blacklist by {message.author} ({message.author.id})")
            return

        elif content.startswith("lc!blacklist remove "):
            domain = content[len("lc!blacklist remove "):].strip().lower()
            if domain in BLACKLIST:
                BLACKLIST.remove(domain)
                save_json_list(BLACKLIST_PATH, BLACKLIST)
                await message.channel.send(f"Removed `{domain}` from blacklist.")
                logging.info(f"Removed `{domain}` from blacklist by {message.author} ({message.author.id})")
            else:
                await message.channel.send(f"`{domain}` is not in the blacklist.")
            return

        elif content == "lc!blacklist show":
            if not BLACKLIST:
                await message.channel.send("Blacklist is empty.")
            else:
                domains = sorted(BLACKLIST)
                chunks = [domains[i:i+20] for i in range(0, len(domains), 30)]
                for i, chunk in enumerate(chunks):
                    await message.channel.send(
                        f"**Blacklisted Domains** (page {i+1}/{len(chunks)}):\n" +
                        "\n".join(f"- `{domain}`" for domain in chunk)
                    )
            return

        elif content == "lc!reload blacklist"  or content == "lc!blacklist reload":
            BLACKLIST = load_json_list(BLACKLIST_PATH)
            await message.channel.send("Blacklist reloaded from file.")
            logging.info("Blacklist reloaded from file.")
            return

        elif content == "lc!help":
            help_message = (
                "**Link Checker Bot Commands:**\n"
                "```"
                "lc!whitelist add <domain>    - Add domain to whitelist\n"
                "lc!whitelist remove <domain> - Remove domain from whitelist\n"
                "lc!whitelist show            - Show whitelisted domains\n"
                "lc!reload whitelist          - Reload whitelist from file\n"
                "lc!whitelist reload          - Same as above\n"
                "lc!blacklist add <domain>    - Add domain to blacklist\n"
                "lc!blacklist remove <domain> - Remove domain from blacklist\n"
                "lc!blacklist show            - Show blacklisted domains\n"
                "lc!reload blacklist          - Reload blacklist from file\n"
                "lc!blacklist reload          - Same as above\n"
                "lc!help                      - Show this help message\n"
                "```"
            )
            await message.channel.send(help_message)
            return
        
        await message.channel.send("Unknown command. Try `lc!help`.")
        return
    
    urls = re.findall(URL_REGEX, message.content)
    for url in urls:
        norm_url = url.lower().strip()
        is_attempting_bypass = False
        await scan_queue.put((message, norm_url, is_attempting_bypass))

client.run(DISCORD_TOKEN)
