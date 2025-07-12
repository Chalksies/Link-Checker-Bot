import discord
import re
import aiohttp
import asyncio
import os
from dotenv import load_dotenv
import base64
import logging
from datetime import datetime

#load .env
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID")) 

#constants
API_RATE_LIMIT = 4 #requests per minute
SCAN_INTERVAL = 60 / API_RATE_LIMIT 

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
scan_queue = asyncio.Queue()
last_scanned_urls = set()

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

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

    await asyncio.sleep(15)  #wait before requesting report

    #fetch report using base64url-encoded URL
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
    async with aiohttp.ClientSession() as session:
        while True:
            message, url = await scan_queue.get()

            if any(blacklisted in url for blacklisted in BLACKLIST):
                try:
                    await message.delete()
                    logging.info(
                        f"[BLACKLIST] Deleted message from {message.author} | URL: {url}"
                    )
                    log_channel = client.get_channel(LOG_CHANNEL_ID)
                    if log_channel:
                        await log_channel.send(
                            f"**Blocked** a message from {message.author.mention}\n (Contained a blacklisted URL)\n"
                            f"> `{url}`\n"
                            f"> `{datetime.utcnow().isoformat()} UTC`"
                        )
                    
                    await message.channel.send(
                        f"Blacklisted link from {message.author.mention} was removed.\n"
                        f"A link in the message was blacklisted by the moderators."
                        )
                    
                except discord.Forbidden:
                    await message.channel.send("Tried to delete a blacklisted link but I lack permissions!")
                await asyncio.sleep(SCAN_INTERVAL)
                scan_queue.task_done()
                continue

            if any(whitelisted in url for whitelisted in WHITELIST):
                scan_queue.task_done()
                continue

            try:
                report = await virus_total_lookup(session, url)
                stats = report["data"]["attributes"]["last_analysis_stats"]
                total_detections = stats.get("malicious", 0)

                if total_detections > 0:
                    try:
                        await message.delete()

                        #log to file
                        logging.info(
                            f"Deleted message from {message.author} ({message.author.id}) | "
                            f"URL: {url} | Detections: {total_detections} | "
                            f"Channel: #{message.channel.name} ({message.channel.id})"
                        )

                        #log to discord channel
                        log_channel = client.get_channel(LOG_CHANNEL_ID)
                        if log_channel:
                            await log_channel.send(
                                f"**Malicious link detected and removed**\n"
                                f"> User: {message.author.mention} (`{message.author.id}`)\n"
                                f"> Channel: {message.channel.mention}\n"
                                f"> URL: `{url}`\n"
                                f"> Detections: `{total_detections}` engines flagged it\n"
                                f"> Time: `{datetime.utcnow().isoformat()} UTC`"
                            )

                        #public warning
                        await message.channel.send(
                        f"Malicious link from {message.author.mention} was removed.\n"
                        f"A link in the message was flagged by VirusTotal ({total_detections} detections)."
                        )
                        print(f"Malicious URL detected: {url} - {total_detections} detections")

                    except discord.Forbidden:
                        await message.channel.send(f"Tried to delete a malicious message but I lack permissions!")
                else:
                    #await message.channel.send(f"VirusTotal scan shows no issues for: {url}")
                    print (f"Safe URL: {url}")
            except Exception as e:
                #await message.channel.send(f"Error scanning {url}: {e}")
                print(f"Error scanning {url}: {e}")
                await log_channel.send(f"Error scanning {url}: {e}. Contact Chalk if this continues.")

            await asyncio.sleep(SCAN_INTERVAL)
            scan_queue.task_done()

#----------------------- bot stuff -----------------------
@client.event
async def on_ready():
    print(f"Logged in as {client.user}")
    client.loop.create_task(scan_worker())

@client.event
async def on_message(message):
    if message.author.bot:
        return

    content = message.content.strip()

    #handle commands
    if content.startswith("lc!"):
        #check permission
        if not message.author.guild_permissions.manage_messages:
            await message.channel.send("You don't have permission to configure the bot!")

            #check if the user is trying to bypass the link checker
            urls = re.findall(URL_REGEX, message.content)
            for url in urls:
                norm_url = url.lower().strip()
                if norm_url not in last_scanned_urls:
                    last_scanned_urls.add(norm_url)
                    await scan_queue.put((message, norm_url))
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

        elif content == "lc!reload whitelist":
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

        elif content == "lc!reload blacklist":
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
                "lc!blacklist add <domain>    - Add domain to blacklist\n"
                "lc!blacklist remove <domain> - Remove domain from blacklist\n"
                "lc!blacklist show            - Show blacklisted domains\n"
                "lc!reload blacklist          - Reload blacklist from file\n"
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
        if norm_url not in last_scanned_urls:
            last_scanned_urls.add(norm_url)
            await scan_queue.put((message, norm_url))

client.run(DISCORD_TOKEN)
