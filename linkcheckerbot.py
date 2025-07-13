import discord
import re
import aiohttp
import asyncio
import os
from dotenv import load_dotenv
import base64
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

#load .env
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID")) 
SILLY_MODE_USER_ID = int(os.getenv("SILLY_MODE_USER_ID"))

#constants
API_RATE_LIMIT = 4 #requests per minute
SCAN_INTERVAL = 60 / API_RATE_LIMIT 
MAX_MALICIOUS_MESSAGES = 3
VIOLATION_WINDOW = timedelta(minutes=2)

WHITELIST_PATH = "whitelist.txt"
WHITELIST = set()

def load_whitelist():
    global WHITELIST
    try:
        with open(WHITELIST_PATH) as f:
            WHITELIST = set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        WHITELIST = set()

def save_whitelist():
    with open(WHITELIST_PATH, "w") as f:
        f.write("\n".join(sorted(WHITELIST)))

BLACKLIST_PATH = "blacklist.txt"
BLACKLIST = set()

def load_blacklist():
    global BLACKLIST
    try:
        with open(BLACKLIST_PATH) as f:
            BLACKLIST = set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        BLACKLIST = set()

def save_blacklist():
    with open(BLACKLIST_PATH, "w") as f:
        f.write("\n".join(sorted(BLACKLIST)))

#call these once on startup
load_whitelist()
load_blacklist()

#link regex
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

#setup file logger
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/malicious_links.log",
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
async def virus_total_lookup(session, url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = { "x-apikey": VT_API_KEY }

    #submit url for scanning
    async with session.post(scan_url, headers=headers, data={"url": url}) as resp:
        if resp.status != 200:
            raise Exception(f"URL submission failed: HTTP {resp.status}")
        submission = await resp.json()

    await asyncio.sleep(10)  #wait before requesting report

    #fetch report using base64url-encoded url
    report_url = f"{scan_url}/{vt_url_id(url)}"
    async with session.get(report_url, headers=headers) as resp:
        if resp.status != 200:
            raise Exception(f"Report fetch failed: HTTP {resp.status}")
        report = await resp.json()

    if "data" not in report or "attributes" not in report["data"]:
        raise Exception(f"Malformed response: {report}")

    return report

#worker to process the scan queue
async def scan_worker():
    while True:
        message, url, is_attempting_bypass = await scan_queue.get()
        norm_url = url.lower().strip()

        try:
            if message.author.guild_permissions.manage_messages:
                #if the user has manage_messages permission, skip checks
                logging.info(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to permissions.")
                continue

            #blacklist check
            if any(blacklisted in norm_url for blacklisted in BLACKLIST):
                await message.delete()
                logging.info(f"[BLACKLIST] Deleted message with blacklisted link: {norm_url} from {message.author} ({message.author.id})")
                await message.channel.send("A blacklisted link was removed.")
                log_channel = client.get_channel(LOG_CHANNEL_ID)
                if log_channel:
                    await log_channel.send(
                        f"`{url}` was removed due to being blacklisted.\n"
                        f" Message author: {message.author.mention} ({message.author.id})\n"
                        f" Timestamp: {datetime.now(timezone.utc).isoformat()}"
                    )
                if is_attempting_bypass:
                    await message.channel.send(
                        f"{message.author.mention}, you attempted to bypass the link checker logic via disguising it as a command. This incident will be reported."
                    )
                    if log_channel:
                        await log_channel.send(
                            f"User {message.author.mention} ({message.author.id}) attempted to bypass the link checker via disguising it as a command.\n"
                            f"Link: `{url}`\n"
                            f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
                        )
                continue

            #already scanned (skip)
            if norm_url in last_scanned_urls:
                continue

            #whitelist check (skip)
            if any(whitelisted in norm_url for whitelisted in WHITELIST):
                continue

            #queue for vt
            await vt_queue.put((message, norm_url, is_attempting_bypass))
            last_scanned_urls.add(norm_url)

        except Exception as e:
            logging.error(f"Error in scan_worker: {e}")
        finally:
            scan_queue.task_done()

async def vt_worker():
    async with aiohttp.ClientSession() as session:
        while True:
            message, url, is_attempting_bypass = await vt_queue.get()
            norm_url = url.lower().strip()

            #default to no deferred messages
            deferred_messages = []

            try:
                #virusTotal Scan
                report = await virus_total_lookup(session, url)
                stats = report["data"]["attributes"]["last_analysis_stats"]
                detections = stats.get("malicious", 0)

                #always clean up the currently being scanned queue
                deferred_messages = scans_in_progress.pop(norm_url, [])

                if detections > 0:
                    log_channel = client.get_channel(LOG_CHANNEL_ID)
                    #blacklist and save
                    BLACKLIST.add(norm_url)
                    save_blacklist()

                    #delete original
                    try:
                        await message.delete()
                        await check_user_violations(message.author, message.channel)
                        await message.channel.send(
                            f"Malicious link from {message.author.mention} removed.\n"
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

                    except Exception as e:
                        logging.warning(f"Failed to delete original malicious message: {e}")


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
    client.loop.create_task(scan_worker())
    client.loop.create_task(vt_worker())

@client.event
async def on_message(message):
    if message.author.bot:
        return

    content = message.content.strip()
    if client.user in message.mentions:
        if message.author.id == SILLY_MODE_USER_ID:
            if message.content == f"<@{client.user.id}>, drone strike this users home.":
                await message.channel.send("Yes ma'am!")
                return

    #handle commands
    if content.startswith("lc!"):
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
            save_whitelist()
            await message.channel.send(f"Added `{domain}` to whitelist.")
            return

        elif content.startswith("lc!whitelist remove "):
            domain = content[len("lc!whitelist remove "):].strip().lower()
            if domain in WHITELIST:
                WHITELIST.remove(domain)
                save_whitelist()
                await message.channel.send(f"Removed `{domain}` from whitelist.")
            else:
                await message.channel.send(f"`{domain}` is not in the whitelist.")
            return

        elif content == "lc!whitelist show":
            if not WHITELIST:
                await message.channel.send("Whitelist is empty.")
            else:
                await message.channel.send(
                    "**Whitelisted Domains:**\n" + "\n".join(f"- `{d}`" for d in sorted(WHITELIST))
                )
            return

        elif content == "lc!reload whitelist" or content == "lc!whitelist reload":
            load_whitelist()
            await message.channel.send("Whitelist reloaded from file.")
            return

        elif content.startswith("lc!blacklist add "):
            domain = content[len("lc!blacklist add "):].strip().lower()
            BLACKLIST.add(domain)
            save_blacklist()
            await message.channel.send(f"Added `{domain}` to blacklist.")
            return

        elif content.startswith("lc!blacklist remove "):
            domain = content[len("lc!blacklist remove "):].strip().lower()
            if domain in BLACKLIST:
                BLACKLIST.remove(domain)
                save_blacklist()
                await message.channel.send(f"Removed `{domain}` from blacklist.")
            else:
                await message.channel.send(f"`{domain}` is not in the blacklist.")
            return

        elif content == "lc!blacklist show":
            if not BLACKLIST:
                await message.channel.send("Blacklist is empty.")
            else:
                await message.channel.send(
                    "**Blacklisted Domains:**\n" + "\n".join(f"- `{d}`" for d in sorted(BLACKLIST))
                )
            return

        elif content == "lc!reload blacklist"  or content == "lc!blacklist reload":
            load_blacklist()
            await message.channel.send("Blacklist reloaded from file.")
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
