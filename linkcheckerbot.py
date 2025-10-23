import discord
from discord import app_commands, PermissionOverwrite
from discord.ui import Button, View
import re
import aiohttp
import asyncio
import os
import base64
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from urllib.parse import urlparse, urlunparse
import tomli
import tomli_w
import json
import time
import uuid
import tldextract

class TTLCache:
    def __init__(self):
        self._data = {}

    def add(self, key: Any, ttl_seconds: int = 300):
        expiry = time.monotonic() + ttl_seconds
        self._data[key] = expiry

    def __contains__(self, key: Any) -> bool:
        expiry = self._data.get(key)
        
        if expiry is None:
            return False
            
        if time.monotonic() > expiry:
            self._data.pop(key, None)
            return False
        
        return True

    def __len__(self) -> int:
        return len(self._data)

DEFAULT_ALLOWLIST = {
    "domains": [
        "discord.com",
        "discordapp.com",
        "youtube.com",
        "youtu.be",
        "google.com",
        "tenor.com",
        "wikipedia.org"
    ]
}

DEFAULT_SHORTENERS = {
    "domains": [
        "bit.ly", 
        "tinyurl.com", 
        "t.co", 
        "goo.gl", 
        "is.gd", 
        "ow.ly", 
        "buff.ly"
    ]
}

DEFAULT_CONFIG = """
[bot]
discord_token = "YOUR_DISCORD_TOKEN"
silly_mode = false
debug_mode = false
responsible_moderator_id = 0            #optional, user ID of the responsible moderator for the bot
scannable_file_extensions = [".exe", ".dll", ".bin", ".dat", ".scr", ".zip", ".rar", ".tar.gz"]
max_file_scan_size_mb = 30    
presence = "Bot is online."

[virustotal]
api_key = "YOUR_VIRUSTOTAL_API_KEY"
scan_sleep = 15
scan_interval_seconds = 5

[moderation]
log_channel_id = 0                 #channel ID for the bot to log its actions
max_violations = 3
violation_window_minutes = 2
threshold = 2
verified_role_name = "Verified"    #role name for verified users. has no effect on scanning
member_role_name = "Member"      #role name for member users. has no effect on scanning.

[structure]
allowlist_path = "allowlist.json"
denylist_path = "denylist.json"
shortener_list_path = "shortener.json"
logging_dir = "logs"
max_log_lines = 5000
violation_path = "violations.json"
stats_path = "stats.json"
fuckup_path = "fuckups.json"
        """


DEFAULT_STATS = {
    "messages_scanned": 0,
    "messages_skipped": 0,
    "virustotal_scans": 0,
    "urls_scanned": 0,
    "attachments_scanned": 0,
    "malicious_urls": 0,
    "malicious_attachments": 0,
    "messages_deleted": 0,
    "shorteners_expanded": 0,
    "violations_logged": 0,
    "allowlist_hits": 0,
    "denylist_hits": 0
}

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
DEBUG_MODE = config["bot"]["debug_mode"]
PRESENCE_TEXT = config ["bot"]["presence"]

LOG_CHANNEL_ID = int(config["moderation"]["log_channel_id"])
SILLY_MODE = bool(config["bot"]["silly_mode"])
SCAN_SLEEP = config["virustotal"]["scan_sleep"]
SCAN_INTERVAL = config["virustotal"]["scan_interval_seconds"]
MAX_MALICIOUS_MESSAGES = config["moderation"]["max_violations"]
VIOLATION_WINDOW = timedelta(minutes=config["moderation"]["violation_window_minutes"])
SCANNABLE_EXTENSIONS = tuple(config["moderation"].get("scannable_file_extensions", []))
MAX_FILE_SIZE = config["moderation"].get("max_file_scan_size_mb", 30) * 1024 * 1024
DELETION_THRESHOLD = config["moderation"]["threshold"]

ALLOWLIST_PATH = config["structure"]["allowlist_path"]
DENYLIST_PATH = config["structure"]["denylist_path"]
SHORTENER_PATH = config["structure"]["shortener_list_path"]
LOGGING_PATH = config["structure"]["logging_dir"]
MAX_LOG_LINES = config["structure"]["max_log_lines"]
VIOLATION_LOG_PATH = config["structure"]["violation_path"]
STATS_PATH = config["structure"]["stats_path"]
FUCKUPS_PATH = config["structure"]["fuckup_path"]

VERIFIED_ROLE_NAME = config["moderation"]["verified_role_name"]
MEMBER_ROLE_NAME = config["moderation"]["member_role_name"]

def save_config():
    with open(CONFIG_PATH, "wb") as f:
        tomli_w.dump(config, f)

if not os.path.exists(ALLOWLIST_PATH):
    print("Default allowlist created, review and modify if needed.")

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

ALLOWLIST = load_json_list(ALLOWLIST_PATH, default=DEFAULT_ALLOWLIST)
DENYLIST = load_json_list(DENYLIST_PATH, default={"domains": []})
SHORTENERS = load_json_list(SHORTENER_PATH, default =DEFAULT_SHORTENERS)

#link regex
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

latest_log_path = os.path.join(LOGGING_PATH, "latest.log")

log_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
log_file_handler = logging.FileHandler(latest_log_path, mode='a', encoding='utf-8')
log_file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_file_handler)

# lockdowns keyed by guild_id then channel_id to support multiple guilds
lockdowns: dict[int, dict[int, dict]] = {}

LOCKDOWN_STATE_PATH = "lockdowns.json"

def save_lockdowns_to_disk(lockdown_data: dict):
    serializable_data = {}
    for guild_id, channels in lockdown_data.items():
        # use string keys for JSON compatibility
        serializable_data[str(guild_id)] = {}
        for channel_id, data in channels.items():
            serializable_data[str(guild_id)][str(channel_id)] = {
                "unlock_at": data["unlock_at"].isoformat() if data.get("unlock_at") else None,
                "prev_everyone": dict(data.get("previous_overwrite_everyone")) if data.get("previous_overwrite_everyone") else None,
                "prev_member": dict(data.get("previous_overwrite_member")) if data.get("previous_overwrite_member") else None,
                "prev_verified": dict(data.get("previous_overwrite_verified")) if data.get("previous_overwrite_verified") else None,
            }
    
    try:
        with open(LOCKDOWN_STATE_PATH, "w") as f:
            json.dump(serializable_data, f, indent=2)
    except Exception as e:
        log_error(f"Failed to save lockdown state: {e}")

def load_lockdowns_from_disk() -> dict:
    if not os.path.exists(LOCKDOWN_STATE_PATH):
        return {}
        
    try:
        with open(LOCKDOWN_STATE_PATH, "r") as f:
            serializable_data = json.load(f)
            
        live_lockdowns = {} 
        
        for guild_id_str, channels in serializable_data.items():
            try:
                guild_id = int(guild_id_str)
            except Exception:
                continue
            live_lockdowns[guild_id] = {}
            for channel_id_str, data in channels.items():
                try:
                    channel_id = int(channel_id_str)
                except Exception:
                    continue

                # parse unlock time safely
                unlock_at = None
                if data.get("unlock_at"):
                    try:
                        unlock_at = datetime.fromisoformat(data.get("unlock_at"))
                        if unlock_at.tzinfo is None:
                            unlock_at = unlock_at.replace(tzinfo=timezone.utc)
                    except Exception:
                        unlock_at = None

                prev_everyone = None
                prev_member = None
                prev_verified = None

                try:
                    if data.get("prev_everyone") is not None:
                        prev_everyone = PermissionOverwrite(**data.get("prev_everyone"))
                except Exception:
                    prev_everyone = None

                try:
                    if data.get("prev_member") is not None:
                        prev_member = PermissionOverwrite(**data.get("prev_member"))
                except Exception:
                    prev_member = None

                try:
                    if data.get("prev_verified") is not None:
                        prev_verified = PermissionOverwrite(**data.get("prev_verified"))
                except Exception:
                    prev_verified = None

                live_lockdowns[guild_id][channel_id] = {
                    "unlock_at": unlock_at,
                    "previous_overwrite_everyone": prev_everyone,
                    "previous_overwrite_member": prev_member,
                    "previous_overwrite_verified": prev_verified,
                    "task": None,
                }
        return live_lockdowns
    except Exception as e:
        log_error(f"Failed to load lockdown state: {e}")
        return {}
    
lockdowns = load_lockdowns_from_disk()

# per-guild settings persistence
GUILD_SETTINGS_PATH = "guild_settings.json"
GUILD_SETTINGS: Dict[str, Dict[str, Any]] = {}


def load_guild_settings():
    global GUILD_SETTINGS
    if not os.path.exists(GUILD_SETTINGS_PATH):
        with open(GUILD_SETTINGS_PATH, "w") as f:
            json.dump({}, f)
        GUILD_SETTINGS = {}
        return
    try:
        with open(GUILD_SETTINGS_PATH, "r", encoding="utf-8") as f:
            GUILD_SETTINGS = json.load(f)
    except Exception:
        GUILD_SETTINGS = {}


def save_guild_settings():
    tmp = GUILD_SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(GUILD_SETTINGS, f, indent=2)
    os.replace(tmp, GUILD_SETTINGS_PATH)


def get_guild_setting(guild: discord.Guild, key: str, fallback=None):
    if guild is None:
        return fallback
    gid = str(guild.id)
    val = GUILD_SETTINGS.get(gid, {}).get(key)
    if val is None:
        return fallback
    return val


def get_log_channel(guild: discord.Guild) -> Optional[discord.TextChannel]:
    # prefer per-guild setting, fallback to global LOG_CHANNEL_ID
    channel_id = get_guild_setting(guild, "log_channel_id", LOG_CHANNEL_ID)
    if not channel_id:
        return None
    return guild.get_channel(int(channel_id))


async def get_responsible_moderator(guild: discord.Guild) -> Optional[discord.User]:
    # prefer per-guild setting, fallback to global RESPONSIBLE_MODERATOR_ID
    mod_id = get_guild_setting(guild, "responsible_moderator_id", RESPONSIBLE_MODERATOR_ID)
    if not mod_id:
        return None
    try:
        return await client.fetch_user(int(mod_id))
    except Exception:
        return None

if os.path.exists(latest_log_path):
    with open(latest_log_path, "r", encoding="utf-8") as f:
        log_line_count = sum(1 for _ in f)
else:
    log_line_count = 0
    with open(latest_log_path, "w", encoding="utf-8") as f:
        pass

def log_and_rotate(message: str, level=logging.INFO):
    global log_line_count, log_file_handler

    logger.log(level, message)
    log_line_count += 1

    if log_line_count >= MAX_LOG_LINES:
        #rotate
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        rotated_path = os.path.join(LOGGING_PATH, f"{timestamp}.log")

        log_file_handler.close()
        os.rename(latest_log_path, rotated_path)

        #start fresh log
        new_handler = logging.FileHandler(latest_log_path, mode='a', encoding='utf-8')
        new_handler.setFormatter(log_formatter)

        logger.removeHandler(log_file_handler)
        logger.addHandler(new_handler)
        log_file_handler = new_handler
        log_line_count = 0

def log_info(msg): log_and_rotate(msg )
def log_warning(msg): log_and_rotate(msg, logging.WARNING)
def log_error(msg): log_and_rotate(msg, logging.ERROR)

if not os.path.exists(STATS_PATH):
    with open(STATS_PATH, "w") as f:
        json.dump(DEFAULT_STATS, f, indent=2)

def load_stats():
    try:
        with open(STATS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_STATS.copy()

def save_stats():
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

stats = load_stats()

def increment_stat(key, amount=1):
    stats[key] = stats.get(key, 0) + amount
    save_stats()

def reset_stats():
    global stats
    stats = DEFAULT_STATS.copy()
    save_stats()
    log_info("Stats have been reset.")

#queue to control rate-limited api use
vt_queue = asyncio.Queue()
scan_queue = asyncio.Queue()
attachment_vt_queue = asyncio.Queue()

last_scanned_urls: set[str] = set()
scans_in_progress: dict[str, list[discord.Message]] = {}
embed_scanned_messages = TTLCache()
deleted_messages = TTLCache()
processed_message_urls = TTLCache()

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
user_violations = defaultdict(list)  # track user violations

tree = app_commands.CommandTree(client)

allowlist_group = app_commands.Group(name="allowlist", description="Manage the allowlist")
denylist_group = app_commands.Group(name="denylist", description="Manage the denylist")
shortener_group = app_commands.Group(name="shortenerlist", description="Manage the shortener list")
config_group = app_commands.Group(name="config", description="Manage the bot configuration")
violations_group = app_commands.Group(name="violations", description="Manage and view link violations")
debug_group = app_commands.Group(name="debug", description="Debugging tools")
manual_group = app_commands.Group(name="manual", description="Scan URLs/Attachments manually.")
stats_group = app_commands.Group(name="stats", description="View and manipulate stats.")
fuckups_group = app_commands.Group(name="fuckup", description="Log and view fuckups.")
moderation_group = app_commands.Group(name="moderate", description="Moderate users anc channels.")
guild_config_group = app_commands.Group(name="config_guild", description="Manage this server's specific settings")

tree.add_command(allowlist_group)
tree.add_command(denylist_group)
tree.add_command(shortener_group)
tree.add_command(config_group)
tree.add_command(violations_group)
tree.add_command(debug_group)
tree.add_command(manual_group)
tree.add_command(stats_group)
tree.add_command(fuckups_group)
tree.add_command(moderation_group)
tree.add_command(guild_config_group)

def read_fuckups() -> List[Dict[str, Any]]:
    try:
        with open(FUCKUPS_PATH, "r") as f:
            content = f.read()
            if not content:
                return []
            return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_fuckups(logs: List[Dict[str, Any]]):
    with open(FUCKUPS_PATH, "w") as f:
        json.dump(logs, f, indent=2)

def log_fuckup(reason: str):

    print(f"Logging event with reason: '{reason}'")
    logs = read_fuckups()
    
    new_event = {
        "timestamp": int(time.time()),
        "reason": reason
    }
    
    logs.append(new_event)
    write_fuckups(logs)

def get_last_fuckup() -> Optional[Dict[str, Any]]:
    logs = read_fuckups()
    
    if not logs:
        return None

    last_event = logs[-1]
    current_time = int(time.time())
    
    last_event["time_since_seconds"] = current_time - last_event["timestamp"]
    
    return last_event

def get_all_fuckups() -> List[Dict[str, Any]]:
    return read_fuckups()

def format_duration(seconds: int) -> str:
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    if days > 0:
        return f"{days}d {hours}h {minutes}m ago"
    elif hours > 0:
        return f"{hours}h {minutes}m ago"
    elif minutes > 0:
        return f"{minutes}m {sec}s ago"
    else:
        return f"{sec}s ago"

def vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded

def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def extract_message_urls(message) -> set:
    urls = set(re.findall(URL_REGEX, message.content or ""))
    normalized_urls = set()
    for url in urls:
        increment_stat("urls_scanned")
        normalized_urls.add(normalize_url(url))
    return normalized_urls

def strip_unbalanced_parenthesis(url):
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    return url

def extract_embed_urls(message) -> set:
    urls = set()
    if not getattr(message, "embeds", None):
        return urls

    for embed in message.embeds:
        candidates: List[str] = []

        if getattr(embed, "url", None):
            candidates.append(embed.url)

        for attr in ("title", "description"):
            val = getattr(embed, attr, None)
            if val:
                candidates.extend(re.findall(URL_REGEX, val))

        for field in getattr(embed, "fields", []):
            val = getattr(field, "value", None)
            if val:
                candidates.extend(re.findall(URL_REGEX, val))

        footer = getattr(embed, "footer", None)
        if footer and getattr(footer, "text", None):
            candidates.extend(re.findall(URL_REGEX, footer.text))

        for u in candidates:
            try:
                normalized = normalize_url(u)
            except Exception:
                normalized = u.strip().lower()

            if normalized:
                increment_stat("urls_scanned")
                urls.add(normalized)

    return urls

async def resolve_short_url(message, url: str, guild: discord.Guild) -> str:
    try:
        parsed = extract_domain(url)
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=True, timeout=5) as resp:
                return str(resp.url)

    except Exception as e:
        log_info(f"Failed to resolve shortener: {e}",  )
        print(f"Failed to resolve shortener: {e}")
        responsible_mod = await get_responsible_moderator(guild)
        if responsible_mod:
            await message.channel.send(
                f"{responsible_mod.mention}, I failed to resolve a shortener: {e}"
            )
        pass
    return url

def normalize_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url.strip().lower())

        #remove default ports
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"

        #remove trailing slash only if path is `/` or empty
        path = parsed.path
        if path == "/":
            path = ""

        #rebuild the normalized url
        normalized = urlunparse((
            parsed.scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        normalized = strip_unbalanced_parenthesis(normalized)

        return normalized
    except Exception:
        return raw_url.strip().lower()

def log_violation(user: discord.User, url: str):
    entry = {
        "id": str(uuid.uuid4()),
        "username": str(user),
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        if os.path.exists(VIOLATION_LOG_PATH):
            with open(VIOLATION_LOG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {}

        user_id = str(user.id)
        if user_id not in data:
            data[user_id] = []

        data[user_id].append(entry)

        with open(VIOLATION_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    except Exception as e:
        log_error(f"Failed to log violation: {e}")

async def _unlock_channel_logic(guild: discord.Guild, channel: discord.TextChannel, prev_everyone, prev_member, prev_verified, reason: str):
    everyone = guild.default_role
    member_role = discord.utils.get(guild.roles, name=MEMBER_ROLE_NAME)
    verified_role = discord.utils.get(guild.roles, name=VERIFIED_ROLE_NAME)

    try:
        if prev_everyone is None:
            await channel.set_permissions(everyone, overwrite=None, reason=reason)
        else:
            await channel.set_permissions(everyone, overwrite=prev_everyone, reason=reason)

        if member_role:
            if prev_member is None:
                await channel.set_permissions(member_role, overwrite=None, reason=reason)
            else:
                await channel.set_permissions(member_role, overwrite=prev_member, reason=reason)

        if verified_role:
            if prev_verified is None:
                await channel.set_permissions(verified_role, overwrite=None, reason=reason)
            else:
                await channel.set_permissions(verified_role, overwrite=prev_verified, reason=reason)
        
        await channel.send("Lockdown expired, channel unlocked.") 

    except Exception as e:
        log_error(f"Failed to auto-unlock channel {channel.id}: {e}")

    finally:
        guild_locks = lockdowns.get(guild.id, {})
        guild_locks.pop(channel.id, None)
        if not guild_locks:
            lockdowns.pop(guild.id, None)
        save_lockdowns_to_disk(lockdowns)

async def auto_unlock(guild: discord.Guild, channel: discord.TextChannel, prev_everyone, prev_member, prev_verified, delay: float):
    try:
        if delay > 0:
            await asyncio.sleep(delay)
        
        log_info(f"Auto-unlocking channel {channel.id} in guild {guild.id}")
        await _unlock_channel_logic(guild, channel, prev_everyone, prev_member, prev_verified, reason="Lockdown expired")

    except asyncio.CancelledError:
        log_info(f"Auto-unlock for channel {channel.id} was cancelled.")
        pass

#virustotal api interaction
async def virustotal_lookup(session, url, channel, guild: discord.Guild):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = { "x-apikey": VT_API_KEY }

    #submit url for scanning
    async with session.post(scan_url, headers=headers, data={"url": url}) as resp:
        if resp.status != 200:
            print(f"URL submission failed for {url}: HTTP {resp.status}")
            log_info(f"URL submission failed for {url}: HTTP {resp.status}",  )
            #log_channel = client.get_channel(LOG_CHANNEL_ID)
            #responsible_mod = await get_responsible_moderator(guild)
            #if log_channel and responsible_mod:
            #    await log_channel.send(
            #        f"{responsible_mod.mention}, I failed to scan a link!\n"
            #        f"(URL submission failed for `{url}`: HTTP {resp.status})"
            #    )

            raise Exception(f"URL submission failed for {url}: HTTP {resp.status}")

    await asyncio.sleep(SCAN_SLEEP)  #wait before requesting report

    #fetch report using base64url-encoded url
    report_url = f"{scan_url}/{vt_url_id(url)}"
    async with session.get(report_url, headers=headers) as resp:
        if resp.status != 200:
            print(f"Report fetch failed for {url}: HTTP {resp.status}")
            responsible_mod = await get_responsible_moderator(guild)
            if responsible_mod:
                await channel.send(
                   f"{responsible_mod.mention}, I failed to scan a link!\n"
                    f"(Report fetch failed: HTTP {resp.status})"
               )

            raise Exception(f"Report fetch failed for {url}: HTTP {resp.status}")
        report = await resp.json()

    if "data" not in report or "attributes" not in report["data"]:
        print(f"Malformed response for {url}: {report}")
        responsible_mod = await get_responsible_moderator(guild)
        if responsible_mod:
           await channel.send(
                f"{responsible_mod.mention}, I failed to scan a link! Check logs.\n"
            )
        raise Exception(f"Malformed response for {url}: {report}")

    return report

async def virustotal_scan_file(session, file_bytes, filename, channel, guild: discord.Guild):
    headers = {"x-apikey": VT_API_KEY}
    
    #uload the file to get an analysis id
    upload_url = "https://www.virustotal.com/api/v3/files"
    form_data = aiohttp.FormData()
    form_data.add_field('file', file_bytes, filename=filename)

    async with session.post(upload_url, headers=headers, data=form_data) as resp:
        if resp.status != 200:
            log_error(f"File upload failed for {filename}: HTTP {resp.status}")
            responsible_mod = await get_responsible_moderator(guild)
            if responsible_mod:
                await channel.send(
                    f"{responsible_mod.mention}, I failed to upload an attachment for scanning!\n"
                    f"(File upload failed for `{filename}`: HTTP {resp.status})"
                )
            raise Exception(f"File upload failed for {filename}: HTTP {resp.status}")
        
        upload_data = await resp.json()
        analysis_id = upload_data["data"]["id"]

    #poll the analysis endpoint until it's complete
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        await asyncio.sleep(SCAN_SLEEP) # Wait before checking the report
        async with session.get(analysis_url, headers=headers) as resp:
            if resp.status != 200:
                log_error(f"File report fetch failed for {filename}: HTTP {resp.status}")
                raise Exception(f"File report fetch failed for {filename}: HTTP {resp.status}")
            
            report = await resp.json()
            status = report.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                return report #analysis is done, return the full report
            elif status == "queued" or status == "inprogress":
                log_info(f"Analysis for {filename} is '{status}'. Waiting...")
                continue
            else:
                log_error(f"Unexpected analysis status for {filename}: {status}")
                raise Exception(f"Unexpected analysis status for {filename}: {status}")

#worker to process the scan queue
async def scan_worker():
    while True:
        message, url = await scan_queue.get()
        domain = extract_domain(url)
        try:
            if domain in SHORTENERS:
                resolved_url = await resolve_short_url(message, url, message.guild) 
                if resolved_url != url:
                    increment_stat("shorteners_expanded")
                    log_info(f"Expanded short URL: {url} → {resolved_url}" )
                    print(f"Expanded short URL: {url} → {resolved_url}")
                url = resolved_url
                domain = extract_domain(url)

            #dedupe same (message, url) processing to avoid duplicate logs
            processed_key = f"{message.id}:{url}"
            if processed_key in processed_message_urls:
                # already processed recently; skip silently
                continue
            processed_message_urls.add(processed_key, ttl_seconds=600)

            #allowlist check (skip)
            if domain in ALLOWLIST:
                log_info(f"Skipping allowlisted link: {url} from {message.author} ({message.author.id}) in #{message.channel}")
                print(f"Skipping allowlisted link: {url}")
                increment_stat("allowlist_hits")
                continue
        
            #denylist check
            if domain in DENYLIST:
                if message.id not in deleted_messages:
                    increment_stat("denylist_hits")
                    try:
                        await message.delete()
                        increment_stat("messages_deleted")
                        deleted_messages.add(message.id, ttl_seconds=300)
                        deleted = True
                        log_info(f"[DENYLIST] Deleted message with denylisted link: {url} from {message.author} ({message.author.id})")
                        await message.channel.send("A denylisted link was removed.")
                        log_violation(message.author, url)
                        increment_stat("violations_logged")
                        
                        log_channel = get_log_channel(message.guild) 
                        if log_channel:
                            await log_channel.send(
                                f" A message containing \"`{url}`\" was removed due to being denylisted.\n"
                                f" Message author: {message.author.mention} ({message.author.id})\n"
                                f" Channel: {message.channel.mention}\n"
                                f" Timestamp: {datetime.now(timezone.utc).isoformat()}"
                            )
                    except discord.NotFound:
                        log_info(f"Message from {message.author} was already removed.")
                        print(f"Message from {message.author} was already removed.")
                    continue

            #queue for vt
            if url in scans_in_progress:
                scans_in_progress[url].append(message)
                log_info(f"Deferred message from {message.author} ({message.author.id}) with URL: {url}" )
                print(f"Deferred message from {message.author} ({message.author.id}) with URL: {url}")
                continue
            else:
                scans_in_progress[url] = []
                await vt_queue.put((message, url))
                log_info(f"Queued for VT: {url} from {message.author} ({message.author.id}) in #{message.channel}")
                print(f"Queued for VT: {url} from {message.author} ({message.author.id}) in #{message.channel}")
                last_scanned_urls.add(url)

        except Exception as e:
            log_error(f"[Scan Worker Error] Failed to process {url}: {e}")
            responsible_moderator = await get_responsible_moderator(message.guild) 
            if responsible_moderator:
                await message.channel.send(
                    f"{responsible_moderator.mention}, I failed to process a link!\n"
                    f"[Scan Worker Error] Error: {e}"
                )
        finally:
            scan_queue.task_done()
            
async def vt_worker():
    async with aiohttp.ClientSession() as session:
        while True:
            message, url = await vt_queue.get()
            guild = message.guild
            deferred_messages = []

            try:
                increment_stat("virustotal_scans")
                #virustotal scan
                report = await virustotal_lookup(session, url, message.channel, guild)
                stats = report["data"]["attributes"]["last_analysis_stats"]
                detections = stats.get("malicious", 0)

                #always clean up the currently being scanned queue
                deferred_messages = scans_in_progress.pop(url, [])

                if detections >= DELETION_THRESHOLD:
                    increment_stat("malicious_urls")
                    log_channel = get_log_channel(guild) 
                    #denylist and save
                    domain = extract_domain(url)
                    if domain not in DENYLIST:
                        DENYLIST.add(domain)
                        log_info(f"Adding {domain} to denylist due to malicious link: {url}")
                        print(f"Adding {domain} to denylist due to malicious link: {url}")
                    save_json_list(DENYLIST_PATH, DENYLIST)

                    log_violation(message.author, url)
                    increment_stat("violations_logged")

                    try:
                        if message.id not in deleted_messages:
                            await message.delete()
                            increment_stat("messages_deleted")
                            deleted_messages.add(message.id, ttl_seconds=300)
                            await check_user_violations(message.author, message.channel)
                    except discord.Forbidden:
                        log_warning(f"Failed to delete message from {message.author} ({message.author.id}) in #{message.channel} due to missing permissions.")
                        responsible_moderator = await get_responsible_moderator(guild)
                        if responsible_moderator:
                            await message.channel.send(
                                f"I tried to delete a message with a malicious link but I don't have permissions, {responsible_moderator.mention}!"
                            )
                        continue
                    except discord.NotFound:
                            log_info(f"Message from {message.author} was already removed.")
                            print(f"Message from {message.author} was already removed.")

                    else:
                        await message.channel.send(
                            f"Malicious link from {message.author.mention} was removed.\n"
                            f"({detections} detections on VirusTotal)"
                        )
                        log_info(f"[MALICIOUS] Deleted: {url} from {message.author} ({message.author.id})")
                        if log_channel: # log_channel is already fetched from above
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
                            if msg.id not in deleted_messages:
                                await msg.delete()
                                increment_stat("messages_deleted")
                                deleted_messages.add(msg.id, ttl_seconds=300)
                                log_violation(msg.author, url)
                                increment_stat("violations_logged")
                                await msg.channel.send(
                                    f"Malicious link from {msg.author.mention} was removed based on recent scan."
                                )
                                await check_user_violations(msg.author, msg.channel)
                                delete_count += 1
                        except discord.NotFound:
                            log_info(f"Deferred message from {msg.author} was already removed.")
                            print(f"Deferred message from {msg.author} was already removed.")
                            pass
                        except Exception as e:
                            log_warning(f"Failed to delete deferred message: {e}")
                            print(f"Failed to delete deferred message: {e}")
                            responsible_moderator = await get_responsible_moderator(guild)
                            if responsible_moderator:
                                await msg.channel.send(f"{responsible_moderator.mention} I failed to delete deferred message: {e}")

                    #log result to moderation channel
                    if log_channel: # log_channel is already fetched from above
                        await log_channel.send(
                            f"`{url}` flagged as malicious by VirusTotal ({detections} detections).\n"
                            f"Original + {delete_count} duplicate messages were removed.\n"
                            f"Original sender: {message.author.mention} ({message.author.id})\n"
                            f"Time: `{datetime.now(timezone.utc).isoformat()}`"
                        )

                else:
                    #safe link
                    print(f"Clean: {url}")
                    log_info(f"[CLEAN] {url} had no detections.")

            except Exception as e:
                log_error(f"[VT Worker Error] Failed to scan {url}: {e}")
                print(f"Error scanning {url}: {e}")
                responsible_mod = await get_responsible_moderator(guild)
                if responsible_mod:
                    await message.channel.send(
                        f"{responsible_mod.mention}, I failed to scan a link!\n"
                        f"[VT Worker Error] Error: {e})"
                    )
                #still pop on error to avoid locking queue
                scans_in_progress.pop(url, None)

            finally:
                await asyncio.sleep(SCAN_INTERVAL) #rate limit to avoid hitting vt too fast
                vt_queue.task_done()

async def attachment_vt_worker():
    async with aiohttp.ClientSession() as session:
        while True:
            message, attachment = await attachment_vt_queue.get()
            guild = message.guild
            try:
                log_info(f"Scanning attachment: {attachment.filename} from {message.author} ({message.author.id})")
                print(f"Scanning attachment: {attachment.filename} from {message.author} ({message.author.id})")
                
                #read file content into memory
                file_bytes = await attachment.read()
                
                #scan the file using vt
                report = await virustotal_scan_file(session, file_bytes, attachment.filename, message.channel, guild)
                stats = report["data"]["attributes"]["stats"]
                detections = stats.get("malicious", 0)

                if detections >= DELETION_THRESHOLD:
                    increment_stat("malicious_attachments")
                    log_info(f"[MALICIOUS ATTACHMENT] Deleted message with attachment: {attachment.filename} from {message.author}")
                    
                    log_violation(message.author, f"malicious attachment: {attachment.filename}")
                    increment_stat("violations_logged")

                    try:
                        await message.delete()
                        increment_stat("messages_deleted")
                        await check_user_violations(message.author, message.channel)
                    except discord.Forbidden:
                        log_warning(f"Failed to delete message with attachment from {message.author} due to missing permissions.")
                        responsible_moderator = await get_responsible_moderator(guild)
                        if responsible_moderator:
                            await message.channel.send(
                                f"I tried to delete a message with a malicious attachment but I don't have permissions, {responsible_moderator.mention}!"
                            )
                        continue
                    except discord.NotFound:
                        log_info(f"Message from {message.author} was already removed.")
                        print(f"Message from {message.author} was already removed.")

                    await message.channel.send(
                        f"Malicious attachment (`{attachment.filename}`) from {message.author.mention} was removed.\n"
                        f"({detections} detections on VirusTotal)"
                    )
                    
                    log_channel = get_log_channel(guild)
                    if log_channel:
                        await log_channel.send(
                            f"Attachment `{attachment.filename}` flagged as malicious by VirusTotal ({detections} detections).\n"
                            f"Message deleted.\n"
                            f"Sender: {message.author.mention} ({message.author.id})\n"
                            f"Time: `{datetime.now(timezone.utc).isoformat()}`"
                        )
                else:
                    log_info(f"[CLEAN ATTACHMENT] {attachment.filename} had no detections.")
                    print(f"[CLEAN ATTACHMENT] {attachment.filename} had no detections.")

            except Exception as e:
                log_error(f"[Attachment Worker Error] Failed to scan {attachment.filename}: {e}")
                responsible_mod = await get_responsible_moderator(guild)
                if responsible_mod:
                     await message.channel.send(
                        f"{responsible_mod.mention}, I failed to scan an attachment!\n"
                        f"[Attachment Worker Error] Error: {e})"
                    )
            finally:
                await asyncio.sleep(SCAN_INTERVAL) #again, avoid hitting vt too much
                attachment_vt_queue.task_done()

async def check_user_violations(user, message_channel):
    now = datetime.now(timezone.utc)
    guild = message_channel.guild
    user_violations[user.id].append(now)

    #keep only recent violations
    user_violations[user.id] = [
        t for t in user_violations[user.id] if now - t <= VIOLATION_WINDOW
    ]

    if len(user_violations[user.id]) >= MAX_MALICIOUS_MESSAGES:
        log_channel = get_log_channel(guild)
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
            responsible_mod = await get_responsible_moderator(guild)
            log_warning(f"Failed to timeout user {user} due to missing permissions.")
            if responsible_mod:
                await message_channel.send(
                    f"I tried to timeout someone for posting multiple malicious links but I don't have permission, {responsible_mod.mention}!"
                )
        
        log_info(f"User {user} exceeded malicious message threshold.")

DURATION_RE = re.compile(r"^(\d+)([smhd])$")

def parse_duration(s: str) -> int:
    m = DURATION_RE.match(s.lower().strip())
    if not m:
        raise ValueError("Bad duration format! Use like 10s, 5m, 2h, 1d")
    val, unit = int(m.group(1)), m.group(2)
    if unit == "s":
        return val
    if unit == "m":
        return val * 60
    if unit == "h":
        return val * 3600
    if unit == "d":
        return val * 86400
    raise ValueError("Unknown unit!")

#----------------------- bot stuff -----------------------
@client.event
async def on_ready():
    await tree.sync()
    await client.change_presence(activity=discord.CustomActivity(name=PRESENCE_TEXT))

    # load per-guild settings (if any)
    try:
        load_guild_settings()
    except Exception:
        log_warning("Failed to load guild settings on startup; continuing with defaults.")

    log_info("Re-initializing persistent lockdowns...")
    now = datetime.now(timezone.utc)
    
    # Iterate through a copy since we may modify the dict
    for guild_id, channels in list(lockdowns.items()):
        guild = client.get_guild(guild_id)
        if not guild:
            log_warning(f"Bot is no longer in guild {guild_id}, clearing its lockdowns.")
            lockdowns.pop(guild_id, None)
            continue
            
        for channel_id, data in list(channels.items()):
            channel = guild.get_channel(channel_id)
            if not channel:
                log_warning(f"Channel {channel_id} no longer exists, clearing its lockdown.")
                channels.pop(channel_id, None)
                continue
                
            unlock_at = data["unlock_at"]
            prev_everyone = data["previous_overwrite_everyone"]
            prev_member = data["previous_overwrite_member"]
            prev_verified = data["previous_overwrite_verified"]
            
            if unlock_at <= now:
                # This lockdown expired while the bot was offline. Unlock immediately.
                log_info(f"Lockdown for {channel.name} expired while offline. Unlocking now.")
                await _unlock_channel_logic(guild, channel, prev_everyone, prev_member, prev_verified, reason="Lockdown expired (offline)")
                # _unlock_channel_logic will remove it from `lockdowns` and save
            else:
                # This lockdown is still active. Re-create the task.
                remaining_seconds = (unlock_at - now).total_seconds()
                log_info(f"Resuming lockdown for {channel.name}. Unlocking in {remaining_seconds:.0f}s.")
                
                task = client.loop.create_task(
                    auto_unlock(guild, channel, prev_everyone, prev_member, prev_verified, delay=remaining_seconds)
                )
                # Store the new task in the in-memory dict
                lockdowns[guild_id][channel_id]["task"] = task
                
    # Save any cleanups (e.g., of old guilds/channels)
    save_lockdowns_to_disk(lockdowns)

    print(f"Logged in as {client.user}")
    log_info(f"Bot started." )
    client.loop.create_task(scan_worker())
    client.loop.create_task(vt_worker())
    client.loop.create_task(attachment_vt_worker())

@allowlist_group.command(name="add", description="Add a domain to the allowlist")
@app_commands.describe(domain="The domain to allowlist (e.g. discord.com)")
async def allowlist_add(interaction: discord.Interaction, domain: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = extract_domain(domain)
    if domain in ALLOWLIST:
        await interaction.response.send_message(f"This domain is already on the allowlist.")
    else:
        ALLOWLIST.add(domain)
        save_json_list(ALLOWLIST_PATH, ALLOWLIST)
        await interaction.response.send_message(f"Added `{domain}` to allowlist.")

@allowlist_group.command(name="remove", description="Remove a domain from the allowlist")
@app_commands.describe(domain="The domain to remove from the allowlist")
async def allowlist_remove(interaction: discord.Interaction, domain: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = normalize_url(domain)
    if domain in ALLOWLIST:
        ALLOWLIST.remove(domain)
        save_json_list(ALLOWLIST_PATH, ALLOWLIST)
        await interaction.response.send_message(f"Removed `{domain}` from allowlist.")
    else:
        await interaction.response.send_message(f"`{domain}` is not in the allowlist.", ephemeral=True)

@allowlist_group.command(name="show", description="Show the current allowlist")
async def allowlist_show(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    if not ALLOWLIST:
        await interaction.response.send_message("Allowlist is empty.")
        return

    domains = sorted(ALLOWLIST)
    await interaction.response.defer()
    chunks = [domains[i:i + 30] for i in range(0, len(domains), 30)]

    embeds = []
    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title=f"Allowlisted Domains (Page {i + 1}/{len(chunks)})",
            description="\n".join(f"• `{domain}`" for domain in chunk),
            color=discord.Color.green()
        )
        embeds.append(embed)

    #send all embeds in a row for now
    for embed in embeds:
        await interaction.followup.send(embed=embed)

@allowlist_group.command(name="reload", description="Reload the allowlist from file")
async def allowlist_reload(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global ALLOWLIST
    ALLOWLIST = load_json_list(ALLOWLIST_PATH)
    await interaction.response.send_message("Allowlist reloaded from file.")

@denylist_group.command(name="add", description="Add a domain to the denylist")
@app_commands.describe(domain="The domain to denylist (e.g. example.com)")
async def denylist_add(interaction: discord.Interaction, domain: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = normalize_url(domain)
    if domain in DENYLIST:
        await interaction.response.send_message(f"This domain is already in the denylist.") 
    else:
        DENYLIST.add(domain)
        save_json_list(DENYLIST_PATH, DENYLIST)
        await interaction.response.send_message(f"Added `{domain}` to denylist.")  

@denylist_group.command(name="remove", description="Remove a domain from the denylist")
@app_commands.describe(domain="The domain to remove from the denylist")
async def denylist_remove(interaction: discord.Interaction, domain: str):  

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = normalize_url(domain)
    if domain in DENYLIST:
        DENYLIST.remove(domain)
        save_json_list(DENYLIST_PATH, DENYLIST)
        await interaction.response.send_message(f"Removed `{domain}` from denylist.")
    else:
        await interaction.response.send_message(f"`{domain}` is not in the denylist.", ephemeral=True)

@denylist_group.command(name="show", description="Show the current denylist")
async def denylist_show(interaction: discord.Interaction): 

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    if not DENYLIST:
        await interaction.response.send_message("Denylist is empty.", ephemeral=True)
        return

    domains = sorted(DENYLIST)
    await interaction.response.defer()
    chunks = [domains[i:i + 30] for i in range(0, len(domains), 30)]

    embeds = []
    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title=f"Denylisted Domains (Page {i + 1}/{len(chunks)})",
            description="\n".join(f"• `{domain}`" for domain in chunk),
            color=discord.Color.red()
        )
        embeds.append(embed)

    #send all embeds in a row for now
    for embed in embeds:
        await interaction.followup.send(embed=embed)

@denylist_group.command(name="reload", description="Reload the denylist from file")
async def denylist_reload(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global DENYLIST
    DENYLIST = load_json_list(DENYLIST_PATH)
    await interaction.response.send_message("Denylist reloaded from file.")

@shortener_group.command(name="add", description="Add a domain to the shortener list")
@app_commands.describe(domain="The domain to add to the shortener list (e.g. bit.ly)")
async def shortenerlist_add(interaction: discord.Interaction, domain: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain = normalize_url(domain)
    if domain in SHORTENERS:
        await interaction.response.send_message(f"This domain is already on the shortener list.")
    else:
        SHORTENERS.add(domain)
        save_json_list(SHORTENER_PATH,SHORTENERS)
        await interaction.response.send_message(f"Added `{domain}` to shortener list.")

@shortener_group.command(name="remove", description="Remove a domain from the shortener list")
@app_commands.describe(domain="The domain to remove from the shortener list")
async def shortenerlist_remove(interaction: discord.Interaction, domain: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    domain = domain = normalize_url(domain)
    if domain in SHORTENERS:
        SHORTENERS.remove(domain)
        save_json_list(SHORTENER_PATH, SHORTENERS)
        await interaction.response.send_message(f"Removed `{domain}` from the shortener list.")
    else:
        await interaction.response.send_message(f"`{domain}` is not in the shortener list.", ephemeral=True)

@shortener_group.command(name="show", description="Show the current shortener list")
async def shortenerlist_show(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    if not SHORTENERS:
        await interaction.response.send_message("Shortener list is empty.")
        return

    domains = sorted(SHORTENERS)
    await interaction.response.defer()
    chunks = [domains[i:i + 30] for i in range(0, len(domains), 30)]

    embeds = []
    for i, chunk in enumerate(chunks):
        embed = discord.Embed(
            title=f"Domains in the shortener list (Page {i + 1}/{len(chunks)})",
            description="\n".join(f"• `{domain}`" for domain in chunk),
            color=discord.Color.blue()
        )
        embeds.append(embed)

    #send all embeds in a row for now
    for embed in embeds:
        await interaction.followup.send(embed=embed)

@shortener_group.command(name="reload", description="Reload the shortener list from file")
async def shortenerlist_reload(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global SHORTENERS
    SHORTENERS = load_json_list(SHORTENER_PATH)
    await interaction.response.send_message("Shortener list reloaded from file.")

@config_group.command(name="show", description="Display the currently loaded configuration")
async def config_show(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    embed = discord.Embed(
        title="Current Configuration",
        color=discord.Color.gold()
    )

    embed.add_field(name="SCAN_SLEEP", value=f"{SCAN_SLEEP}s", inline=False)
    embed.add_field(name="SCAN_INTERVAL", value=f"{SCAN_INTERVAL}s", inline=False)
    embed.add_field(name="MAX_MALICIOUS_MESSAGES", value=str(MAX_MALICIOUS_MESSAGES), inline=False)
    embed.add_field(name="VIOLATION_WINDOW", value=f"{int(VIOLATION_WINDOW.total_seconds() // 60)} minutes", inline=False)
    embed.add_field(name="LOG_CHANNEL_ID", value=f"`{LOG_CHANNEL_ID}`", inline=False)
    embed.add_field(name="RESPONSIBLE_MODERATOR_ID", value=f"`{RESPONSIBLE_MODERATOR_ID}`", inline=False)

    await interaction.response.send_message(embed=embed)


@config_group.command(name="reload", description="Reload the bot configuration from file")
async def config_reload(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    global config
    global DISCORD_TOKEN
    global VT_API_KEY
    global RESPONSIBLE_MODERATOR_ID
    global DEBUG_MODE
    global PRESENCE_TEXT
    global LOG_CHANNEL_ID
    global SILLY_MODE
    global SCAN_SLEEP
    global SCAN_INTERVAL
    global MAX_MALICIOUS_MESSAGES
    global VIOLATION_WINDOW
    global SCANNABLE_EXTENSIONS
    global MAX_FILE_SIZE
    global ALLOWLIST_PATH 
    global DENYLIST_PATH 
    global SHORTENER_PATH 
    global LOGGING_PATH 
    global MAX_LOG_LINES 
    global VIOLATION_LOG_PATH 
    global STATS_PATH 
    global FUCKUPS_PATH
    global DELETION_THRESHOLD

    config = load_config()

    DISCORD_TOKEN = config["bot"]["discord_token"]
    VT_API_KEY = config["virustotal"]["api_key"]
    RESPONSIBLE_MODERATOR_ID = config["bot"]["responsible_moderator_id"]
    DEBUG_MODE = config["bot"]["debug_mode"]
    PRESENCE_TEXT = config ["bot"]["presence"]

    LOG_CHANNEL_ID = int(config["moderation"]["log_channel_id"])
    SILLY_MODE = bool(config["bot"]["silly_mode"])
    SCAN_SLEEP = config["virustotal"]["scan_sleep"]
    SCAN_INTERVAL = config["virustotal"]["scan_interval_seconds"]
    MAX_MALICIOUS_MESSAGES = config["moderation"]["max_violations"]
    VIOLATION_WINDOW = timedelta(minutes=config["moderation"]["violation_window_minutes"])
    SCANNABLE_EXTENSIONS = tuple(config["moderation"].get("scannable_file_extensions", []))
    MAX_FILE_SIZE = config["moderation"].get("max_file_scan_size_mb", 30) * 1024 * 1024
    DELETION_THRESHOLD = config["moderation"]["threshold"]

    ALLOWLIST_PATH = config["structure"]["allowlist_path"]
    DENYLIST_PATH = config["structure"]["denylist_path"]
    SHORTENER_PATH = config["structure"]["shortener_list_path"]
    LOGGING_PATH = config["structure"]["logging_dir"]
    MAX_LOG_LINES = config["structure"]["max_log_lines"]
    VIOLATION_LOG_PATH = config["structure"]["violation_path"]
    STATS_PATH = config["structure"]["stats_path"]
    FUCKUPS_PATH = config["structure"]["fuckup_path"]
    await client.change_presence(activity=discord.CustomActivity(name=PRESENCE_TEXT))
    await interaction.response.send_message("Configuration reloaded from file.")

CONFIG_KEYS = ["SCAN_SLEEP", "SCAN_INTERVAL", "MAX_MALICIOUS_MESSAGES", "VIOLATION_WINDOW", "LOG_CHANNEL_ID", "RESPONSIBLE_MODERATOR_ID", "DELETION_THRESHOLD"]

async def config_key_autocomplete(interaction: discord.Interaction, current: str):
    return [
        app_commands.Choice(name=key, value=key)
        for key in CONFIG_KEYS
        if current.lower() in key.lower()
    ][:25]

@config_group.command(name="edit", description="Edit a config option.")
@app_commands.describe(key="Name of the config key (/help for details)", value="New value for the config key")
@app_commands.autocomplete(key=config_key_autocomplete)
async def config_edit(interaction: discord.Interaction, key: str, value: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return
    
    key = key.lower()

    if key == "scan_sleep":
        global SCAN_SLEEP
        SCAN_SLEEP = int(value)
        config["virustotal"]["scan_sleep"] = SCAN_SLEEP
    elif key == "scan_interval":
        global SCAN_INTERVAL
        SCAN_INTERVAL = int(value)
        config["virustotal"]["scan_interval_seconds"] = SCAN_INTERVAL
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
    elif key == "responsible_moderator_id": 
        global RESPONSIBLE_MODERATOR_ID
        RESPONSIBLE_MODERATOR_ID = int(value)
        config["bot"]["responsible_moderator_id"] = RESPONSIBLE_MODERATOR_ID
    elif key == "deletion_threshold":
        global DELETION_THRESHOLD
        DELETION_THRESHOLD = int(value)
        config["moderation"]["threshold"] = DELETION_THRESHOLD
    else:
        await interaction.response.send_message(
            f"Unknown config key: `{key}`\n"
            f"Available keys are: scan_sleep, scan_interval, max_malicious_messages, violation_window_minutes, log_channel_id, responsible_moderator_id", 
            ephemeral=True)
        return
    
    try: 
        save_config()
        await interaction.response.send_message(f"Updated `{key}` to `{value}` and saved to config file.")
    except Exception as e:
        await interaction.response.send_message(f"Failed to save config to file: {e}", ephemeral=True)
        return
    
@config_group.command(name="toggle_debug", description="Toggle debug mode")
async def config_toggle_debug(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("Permission denied.", ephemeral=True)
        return

    global DEBUG_MODE
    DEBUG_MODE = not DEBUG_MODE
    config["bot"]["debug_mode"] = DEBUG_MODE
    save_config()

    await interaction.response.send_message(f"Debug mode is now **{'enabled' if DEBUG_MODE else 'disabled'}**.")

@guild_config_group.command(name="set_log_channel", description="Set this server's private log channel")
@app_commands.describe(channel="The channel to log to (or None to use global default)")
async def config_guild_set_log(interaction: discord.Interaction, channel: Optional[discord.TextChannel]):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("You are not authorized to do this.", ephemeral=True)
        return
        
    gid = str(interaction.guild.id)
    if gid not in GUILD_SETTINGS:
        GUILD_SETTINGS[gid] = {}

    if channel is None:
        GUILD_SETTINGS[gid].pop("log_channel_id", None)
        save_guild_settings()
        await interaction.response.send_message("This server's log channel has been reset. I will now use the global default.", ephemeral=True)
    else:
        GUILD_SETTINGS[gid]["log_channel_id"] = channel.id
        save_guild_settings()
        await interaction.response.send_message(f"This server's log channel has been set to {channel.mention}.")

@guild_config_group.command(name="set_responsible_moderator", description="Set this server's responsible moderator")
@app_commands.describe(user="The moderator to ping for issues (or None to use global default)")
async def config_guild_set_mod(interaction: discord.Interaction, user: Optional[discord .User]):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("You are not authorized to do this.", ephemeral=True)
        return
        
    gid = str(interaction.guild.id)
    if gid not in GUILD_SETTINGS:
        GUILD_SETTINGS[gid] = {}

    if user is None:
        GUILD_SETTINGS[gid].pop("responsible_moderator_id", None)
        save_guild_settings()
        await interaction.response.send_message("This server's responsible moderator has been reset. I will now use the global default.", ephemeral=True)
    else:
        GUILD_SETTINGS[gid]["responsible_moderator_id"] = user.id
        save_guild_settings()
        await interaction.response.send_message(f"This server's responsible moderator has been set to {user.mention}.")
    
@violations_group.command(name="show", description="Show all violations for a user")
@app_commands.describe(user="The user to view violations for (optional)")
async def violations_show(interaction: discord.Interaction, user: Optional[discord.User]):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    try:
        if not os.path.exists(VIOLATION_LOG_PATH):
            await interaction.response.send_message("No violations have been recorded yet.")
            return
        
        with open(VIOLATION_LOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)


        violations_list = []
        embed_title = ""

        if user:
            user_id = str(user.id)
            violations_list = data.get(user_id, [])
            embed_title = f"Violations for {user}"

            if not violations_list:
                await interaction.response.send_message(f"No violations recorded for {user.mention}.")
                return
        else:
            embed_title = "All Violations"
            all_violations = []
            for uid, vlist in data.items():
                all_violations.extend(vlist)
            
            if not all_violations:
                await interaction.response.send_message("No violations have been recorded yet.")
                return

            all_violations.sort(key=lambda x: x["timestamp"], reverse=True)
            violations_list = all_violations


        #build response
        embed = discord.Embed(
            title=f"Violations for {user}",
            description=f"Total: {len(violations_list)}",
            color=discord.Color.red()
        )

        for v in violations_list[:10]:
            username = v.get("username", "Unknown User")

            value_text = f"**User:** `{username}`\n" \
                         f"**ID:** `{v.get('id', 'NO_ID')}`\n" \
                         f"**Link:** `{v['url']}`"
            
            embed.add_field(
                name=v["timestamp"],
                value=value_text,
                inline=False
            )

        if len(violations_list) > 10:
            embed.set_footer(text=f"Showing first 10 of {len(violations_list)} violations. Use /violations remove <user ><id> to remove one.")
        else:
            embed.set_footer(text=f"Use /violations remove <id> to remove one.")

        await interaction.response.send_message(embed=embed)

    except Exception as e:
        log_error(f"Failed to show violations: {e}")
        await interaction.response.send_message("Error loading violations log.", ephemeral=True)

@violations_group.command(name="remove", description="Remove a specific violation entry by its ID")
@app_commands.describe(user="The user who the violation was logged against", violation_id="The unique ID of the violation to remove")
async def violations_remove(interaction: discord.Interaction, user: discord.User, violation_id: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    try:
        if not os.path.exists(VIOLATION_LOG_PATH):
            await interaction.followup.send("No violations have been recorded yet.")
            return
        
        with open(VIOLATION_LOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        user_id = str(user.id)
        violations = data.get(user_id, [])

        if not violations:
            await interaction.followup.send(f"No violations recorded for {user.mention}.")
            return

        violation_to_remove = None
        for v in violations:
            if v.get('id') == violation_id:
                violation_to_remove = v
                break
        
        if violation_to_remove is None:
            await interaction.followup.send(f"Could not find a violation with ID `{violation_id}` for {user.mention}.")
            return

        violations.remove(violation_to_remove)
        data[user_id] = violations
        
        with open(VIOLATION_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        await interaction.followup.send(f"Successfully removed violation `{violation_id}` (Link: `{violation_to_remove['url']}`) for {user.mention}.")
        log_info(f"Violation {violation_id} removed for user {user.id} by {interaction.user}.")

    except Exception as e:
        log_error(f"Failed to remove violation: {e}")
        await interaction.followup.send(f"An error occurred: {e}")

@manual_group.command(name="check_link", description="Manually scan a link via the VirusTotal API")
@app_commands.describe(url="The full URL to scan (including http/https)")
async def debug_manual_check(interaction: discord.Interaction, url: str):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    await interaction.response.defer(thinking=True)
 
    try:
        norm_url = normalize_url(url)
        increment_stat("urls_scanned")
    except Exception as e:
        await interaction.followup.edit_original_response(f"An error occured while resolving URL: {e}")

    if extract_domain(norm_url) in SHORTENERS:
        await interaction.followup.edit_original_response(f"`{norm_url}` is a shortener. Resolving...")
        try:
            norm_url = await resolve_short_url(interaction, norm_url, interaction.guild)
            increment_stat("shorteners_expanded")
        except Exception as e:
            await interaction.followup.edit_original_response(f"Failed to resolve shortener: {e}")

    domain = extract_domain(norm_url)

    if domain in ALLOWLIST:
        await interaction.followup.edit_original_response(f"`{norm_url}` is in the allowlist. It will not be scanned.")
        increment_stat("allowlist_hits")
        return

    if domain in DENYLIST:
        await interaction.followup.edit_original_response(f"`{norm_url}` is in the denylist! It will not be scanned.")
        increment_stat("denylist_hits")
        return
    
    await interaction.followup.edit_original_response(f"This might take a while... (15~ seconds)")

    async with aiohttp.ClientSession() as session:
        try:
            increment_stat("virustotal_scans")
            report = await virustotal_lookup(session, norm_url, interaction.channel, interaction.guild)
            stats = report["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values())

            verdict = (
                "Malicious"
                if malicious > 0 else
                "Suspicious"
                if suspicious > 0 else
                "Clean"
            )

            # get short list of engines that flagged it
            flagged = [
                name for name, result in report["data"]["attributes"]["last_analysis_results"].items()
                if result["category"] in {"malicious", "suspicious"}
            ][:10]

            embed = discord.Embed(
                title=f"VirusTotal Scan for {norm_url}",
                description=f"Verdict: **{verdict}**",
                color=discord.Color.red() and increment_stat("malicious_urls") if malicious > 0 else discord.Color.orange() if suspicious > 0 else discord.Color.green()
            )
            embed.add_field(name="Malicious", value=str(malicious), inline=True)
            embed.add_field(name="Suspicious", value=str(suspicious), inline=True)
            embed.add_field(name="Harmless", value=str(harmless), inline=True)
            embed.add_field(name="Flagged by", value=", ".join(flagged) if flagged else "None", inline=False)
            embed.set_footer(text=f"Scanned via /check by {interaction.user}", icon_url=interaction.user.display_avatar.url)

            await interaction.edit_original_response(embed=embed)

        except Exception as e:
            await interaction.followup.edit_original_response(f"Failed to scan the link: {e}")
            log_error(f"[Manual Check Error] {url}: {e}")

@manual_group.command(name="check_file", description="Manually scan a file attachment via the VirusTotal API")
@app_commands.describe(file="The file to scan")
async def manual_check_file(interaction: discord.Interaction, file: discord.Attachment):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    await interaction.response.defer(thinking=True)

    #validate file against configured rules
    if not file.filename.lower().endswith(SCANNABLE_EXTENSIONS):
        await interaction.followup.send(f"The file type `{file.filename.split('.')[-1]}` is not in the scannable list. No action will be taken.", ephemeral=True)
        return

    if file.size > MAX_FILE_SIZE:
        await interaction.followup.send(f"The file `{file.filename}` is too large to be scanned ({file.size / 1024 / 1024:.2f}MB).", ephemeral=True)
        return

    await interaction.followup.send(f"Uploading and scanning `{file.filename}`... This might take a moment.")
    increment_stat("attachments_scanned")

    try:
        async with aiohttp.ClientSession() as session:
            file_bytes = await file.read()
            report = await virustotal_scan_file(session, file_bytes, file.filename, interaction.channel, interaction.guild)

            stats = report["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            verdict = "Malicious" if malicious > 0 else "Suspicious" if suspicious > 0 else "Clean"
            
            color = discord.Color.red() if malicious > 0 else discord.Color.orange() if suspicious > 0 else discord.Color.green()
            if malicious > 0:
                increment_stat("malicious_attachments")

            #get a short list of engines that flagged it
            flagged_by = [
                name for name, result in report["data"]["attributes"]["results"].items()
                if result["category"] in {"malicious", "suspicious"}
            ][:10]

            embed = discord.Embed(
                title=f"VirusTotal Scan for {file.filename}",
                description=f"Verdict: **{verdict}**",
                color=color
            )
            embed.add_field(name="Malicious", value=str(malicious), inline=True)
            embed.add_field(name="Suspicious", value=str(suspicious), inline=True)
            embed.add_field(name="Harmless/Undetected", value=str(harmless), inline=True)
            embed.add_field(name="Flagged By", value=", ".join(flagged_by) if flagged_by else "None", inline=False)
            embed.set_footer(text=f"Scanned via /check_file by {interaction.user}", icon_url=interaction.user.display_avatar.url)

            await interaction.edit_original_response(content=None, embed=embed)

    except Exception as e:
        log_error(f"[Manual File Check Error] {file.filename}: {e}")
        await interaction.edit_original_response(content=f"An error occurred while scanning the file: {e}")


@debug_group.command(name="throw_error", description="Manually raise a test exception")
async def debug_throw_error(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return
    
    if not DEBUG_MODE:
        await interaction.response.send_message("Debug mode is disabled.", ephemeral=True)
        return

    await interaction.response.send_message("An error was thrown into logs.")
    raise RuntimeError("This is a manually thrown test error.")

@debug_group.command(name="throw_warning", description="Manually trigger a warning log")
async def debug_throw_warning(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return
    
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return
    
    if not DEBUG_MODE:
        await interaction.response.send_message("Debug mode is disabled.", ephemeral=True)
        return

    log_warning(f"Debug warning triggered by {interaction.user} ({interaction.user.id})")
    await interaction.response.send_message("A warning was thrown into logs.")
    
@tree.command(name="ping", description="Show bot latency and response time")
async def ping_command(interaction: discord.Interaction):

    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return

    heartbeat = round(client.latency * 1000)

    await interaction.response.defer()
    before = discord.utils.utcnow()

    await interaction.followup.send("Measuring...")  #throwaway message

    after = discord.utils.utcnow()
    roundtrip = round((after - before).total_seconds() * 1000)

    embed = discord.Embed(
        title="Pong :3",
        color=discord.Color.teal()
    )
    embed.add_field(name="Heartbeat Latency", value=f"{heartbeat}ms", inline=True)
    embed.add_field(name="Roundtrip Latency", value=f"{roundtrip}ms", inline=True)

    #update the message with real data
    await interaction.edit_original_response(content=None, embed=embed)

@stats_group.command(name="show", description="Show stats")
async def stats_show_command(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return
        
    embed = discord.Embed(
        title="Bot Stats",
        color=discord.Color.blurple()
    )

    embed.add_field(name="Messages Scanned for URLs", value=str(stats["messages_scanned"]), inline=False)
    embed.add_field(name="Messages Skipped", value=str(stats["messages_skipped"]), inline=False)
    embed.add_field(name="URLs Found", value=str(stats["urls_scanned"]), inline=False)
    
    embed.add_field(name="Shorteners Expanded", value=str(stats["shorteners_expanded"]), inline=False)
    embed.add_field(name="Attachments Scanned", value=str(stats["attachments_scanned"]), inline=False) 
    embed.add_field(name="Malicious Attachments", value=str(stats["malicious_attachments"]), inline=False) 
    embed.add_field(name="Virustotal Scans", value=str(stats["virustotal_scans"]), inline=False) 

    embed.add_field(name="Allowlist Hits", value=str(stats["allowlist_hits"]), inline=False)
    embed.add_field(name="Denylist Hits", value=str(stats["denylist_hits"]), inline=False)
    embed.add_field(name="Malicious URLs Detected", value=str(stats["malicious_urls"]), inline=False)

    embed.add_field(name="Messages Deleted", value=str(stats["messages_deleted"]), inline=False)
    embed.add_field(name="Violations Logged", value=str(stats["violations_logged"]), inline=False)

    embed.add_field(name="Allowlist Size", value=str(len(ALLOWLIST)), inline=False)
    embed.add_field(name="Denylist Size", value=str(len(DENYLIST)), inline=False)
    embed.add_field(name="Shortener List Size", value=str(len(SHORTENERS)), inline=False)

    await interaction.response.send_message(embed=embed)

@stats_group.command(name="reset", description="Reset stats")
async def stats_reset_command(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You don't have permission to do this.", ephemeral=True)
        return

    #define custom view for buttons
    class ConfirmationView(View):
        def __init__(self, original_interaction: discord.Interaction):
            super().__init__(timeout=60)
            self.original_interaction = original_interaction
            self.confirmed = False

        @discord.ui.button(label="Yes, I'm sure", style=discord.ButtonStyle.danger)
        async def confirm_button(self, interaction: discord.Interaction, button: Button):
            if interaction.user != self.original_interaction.user:
                await interaction.response.send_message("This isn't your confirmation!", ephemeral=True)
                return

            self.confirmed = True
            self.stop()

            #acknowledge the button click immediately
            await interaction.response.defer()
            await self.original_interaction.edit_original_response(
                content="Stats have been reset.",
                view=None
            )

            reset_stats()
            print(f"Stats reset by {interaction.user.name}")
            log_info(f"Stats reset by {interaction.user.name}")


        @discord.ui.button(label="No, cancel", style=discord.ButtonStyle.secondary)
        async def cancel_button(self, interaction: discord.Interaction, button: Button):
            if interaction.user != self.original_interaction.user:
                await interaction.response.send_message("This isn't your cancellation!", ephemeral=True)
                return

            self.confirmed = False
            self.stop()
            await interaction.response.defer()

            await self.original_interaction.edit_original_response(
                content="Stats reset cancelled.",
                view=None
            )
            print(f"{interaction.user.name} cancelled stats reset.")

        async def on_timeout(self, ):
            if not self.confirmed:
                try:
                    await self.original_interaction.edit_original_response(
                        content="Confirmation timed out. Stats reset cancelled.",
                        view=None
                    )
                except discord.errors.NotFound:
                    #interaction might have been deleted by user or bot
                    pass
    view = ConfirmationView(interaction)
    await interaction.response.send_message("Are you sure you want to reset all stats? This action cannot be undone!", view=view)

@fuckups_group.command(name="log", description="Log a fuckup")
@app_commands.describe(reason="Reason of the fuckup")
async def fuckup_log_command(interaction: discord.Interaction, reason:str):
    log_fuckup(reason)
    await interaction.response.send_message(f"Logged a fuckup: **{reason}**")
    log_info(f"Logged a fuckup: {reason}")

@fuckups_group.command(name="last", description="Show last fuckup")
async def lastfuckup(interaction: discord.Interaction):
    last = get_last_fuckup()
    if not last:
        await interaction.response.send_message("No fuckups logged yet.")
        return

    ts = last["timestamp"]
    reason = last["reason"]
    delta = last["time_since_seconds"]
    human_readable = format_duration(delta)

    await interaction.response.send_message(
        f"**Last fuckup**:\nReason: {reason}\nTimestamp: <t:{ts}:F> ({human_readable})"
    )

@fuckups_group.command(name="all", description="Show all fuckups")
async def allfuckups(interaction: discord.Interaction):
    logs = get_all_fuckups()
    if not logs:
        await interaction.response.send_message("No fuckups logged yet.")
        return

    messages = [f"{i+1}. <t:{log['timestamp']}:F> - {log['reason']}" for i, log in enumerate(logs)]
    joined = "\n".join(messages)
    if len(joined) > 1990:
        joined = joined[:1990] + "..."

    await interaction.response.send_message(f"**All fuckups:**\n{joined}")
    
class HelpView(discord.ui.View):
    def __init__(self, embeds: List[discord.Embed], original_user: discord.User):
        super().__init__(timeout=180.0) 
        self.embeds = embeds
        self.original_user = original_user
        self.current_page = 0
        self.message: Optional[discord.Message] = None
        
        for i, embed in enumerate(self.embeds):
            embed.set_footer(text=f"Page {i + 1}/{len(self.embeds)}")
        
        self.update_buttons()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.original_user.id:
            await interaction.response.send_message("You can't control this help menu.", ephemeral=True)
            return False
        return True

    def update_buttons(self):
        self.prev_button.disabled = self.current_page == 0
        self.next_button.disabled = self.current_page == (len(self.embeds) - 1)

    @discord.ui.button(label="Previous", style=discord.ButtonStyle.primary, custom_id="help_prev")
    async def prev_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.current_page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)

    @discord.ui.button(label="Next", style=discord.ButtonStyle.primary, custom_id="help_next")
    async def next_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.current_page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, custom_id="help_close")
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.stop()
        await interaction.response.edit_message(view=None)

    async def on_timeout(self):
        if self.message:
            try:
                for item in self.children:
                    item.disabled = True
                await self.message.edit(view=self)
            except discord.NotFound:
                pass


@tree.command(name="help", description="Show help and usage info")
async def help_command(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("I don't currently support DMs!", ephemeral=True)
        return

    is_admin = interaction.user.guild_permissions.manage_messages
    embeds_list = []

    embed_page_1 = discord.Embed(
        title="LinkChecker Bot Help",
        description="I monitor and scan links in messages and embeds. Malicious links are deleted and logged automatically.",
        color=discord.Color.blurple()
    )
    embed_page_1.add_field(
        name="General Commands",
        value="• `/ping` - Show bot latency.\n"
              "• `/help` - Show this help menu.\n"
              "Other commands are for moderators only.",
        inline=False
    )
    
    if is_admin:
        embed_page_1.add_field(
            name="Core Moderation Tools",
            value="• `/manual check_link <url>` - Manually scan a URL.\n"
                  "• `/manual check_file <file>` - Manually scan an attachment.\n"
                  "• `/violations show <user>` - Show violations for a user.\n"
                  "• `/stats show` - Show bot stats.\n"
                  "• `/stats reset` - Reset bot stats.",
            inline=False
        )
    embeds_list.append(embed_page_1)

    if is_admin:
        embed_page_2 = discord.Embed(
            title="Admin: Server & Config",
            color=discord.Color.gold()
        )
        embed_page_2.add_field(
            name="Channel Moderation",
            value="• `/moderate lockdown <duration> <reason>` - Lock a channel.\n"
                  "• `/moderate unlock` - Unlock a channel manually.\n"
                  "• `/panic_stop` - Stop the bot in an emergency.",
            inline=False
        )
        embed_page_2.add_field(
            name="Guild-Specific Config",
            value="• `/config_guild set_log_channel [channel]` - Set this server's log channel.\n"
                  "• `/config_guild set_responsible_moderator [user]` - Set this server's mod to ping.",
            inline=False
        )
        embed_page_2.add_field(
            name="Global Bot Config",
            value="• `/config show` - Show global config.\n"
                  "• `/config edit <key> <value>` - Edit global config.\n"
                  "• `/config reload` - Reload global config from file.\n"
                  "• `/config toggle_debug` - Toggle debug mode.",
            inline=False
        )
        embed_page_2.add_field(
            name="Bot Control (Owner Only)",
            value="• `/say <message> <channel> <reply>` - Make the bot say something.",
            inline=False
        )
        embeds_list.append(embed_page_2)

        embed_page_3 = discord.Embed(
            title="Admin: List Management",
            color=discord.Color.green()
        )
        embed_page_3.add_field(
            name="Allowlist",
            value="• `/allowlist add <domain>`\n"
                  "• `/allowlist remove <domain>`\n"
                  "• `/allowlist show`\n"
                  "• `/allowlist reload`",
            inline=False
        )
        embed_page_3.add_field(
            name="Denylist",
            value="• `/denylist add <domain>`\n"
                  "• `/denylist remove <domain>`\n"
                  "• `/denylist show`\n"
                  "• `/denylist reload`",
            inline=False
        )
        embed_page_3.add_field(
            name="Shorteners",
            value="• `/shortenerlist add <domain>`\n"
                  "• `/shortenerlist remove <domain>`\n"
                  "• `/shortenerlist show`\n"
                  "• `/shortenerlist reload`",
            inline=False
        )
        embeds_list.append(embed_page_3)

        embed_page_4 = discord.Embed(
            title="Admin: Misc & Debug",
            color=discord.Color.greyple()
        )
        embed_page_4.add_field(
            name="Fuckup Logging",
            value="• `/fuckup log <reason>`\n"
                  "• `/fuckup last`\n"
                  "• `/fuckup all`",
            inline=False
        )
        if DEBUG_MODE:
            embed_page_4.add_field(
                name="Debugging Tools (Debug Mode ON)",
                value="• `/debug throw_error`\n"
                      "• `/debug throw_warning`",
                inline=False
            )
        embeds_list.append(embed_page_4)

    embed_page_notes = discord.Embed(
        title="Bot Functionality Notes",
        color=discord.Color.blurple()
    )
    embed_page_notes.add_field(
        name="How I work",
        value="• Links in sent messages, their embeds, and edited messages are scanned.\n"
              "• Shortened URLs (e.g. `bit.ly`) are automatically resolved.\n"
              "• Malicious links found by VirusTotal are automatically denylisted.\n"
              "• Users spamming bad links are timed out and logged.",
        inline=False
    )
    embeds_list.append(embed_page_notes)

    view = HelpView(embeds_list, interaction.user)
    await interaction.response.send_message(embed=embeds_list[0], view=view)
    
    view.message = await interaction.original_response()

@moderation_group.command(name="lockdown", description="Initiate a channel lockdown.")
@app_commands.describe(duration="How long to lock the channel (10s, 5m, 2h, 1d)", reason="Reason for the lockdown")
async def lockdown(interaction: discord.Interaction, duration: str, reason: str = "No reason provided"):


    if interaction.guild is None:
        await interaction.response.send_message(f"I don't currently support DMs!")
        return
    
    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You are not authroized to do this.")
        return
    
    try:
        seconds = parse_duration(duration)
    except ValueError as e:
        await interaction.response.send_message(str(e), ephemeral=True)
        return
    
    channel = interaction.channel
    guild = interaction.guild
    everyone = interaction.guild.default_role
    member_role = discord.utils.get(interaction.guild.roles, name=MEMBER_ROLE_NAME)
    verified_role = discord.utils.get(interaction.guild.roles, name=VERIFIED_ROLE_NAME)


    # ensure per-guild map exists
    guild_locks = lockdowns.setdefault(interaction.guild.id, {})
    if channel.id in guild_locks:
        await interaction.response.send_message("This channel is already locked.", ephemeral=True)
        return


    prev_everyone = channel.overwrites_for(everyone)
    prev_member = channel.overwrites_for(member_role) if member_role else None
    prev_verified = channel.overwrites_for(verified_role) if verified_role else None


    # avoid mutating the original overwrites
    if prev_everyone is not None:
        overwrite_everyone = PermissionOverwrite(**dict(prev_everyone))
    else:
        overwrite_everyone = PermissionOverwrite()
    overwrite_everyone.send_messages = False
    overwrite_everyone.send_messages_in_threads = False
    await channel.set_permissions(everyone, overwrite=overwrite_everyone, reason=f"Lockdown by {interaction.user} - {reason}")

    if member_role:
        if prev_member is not None:
            overwrite_member = PermissionOverwrite(**dict(prev_member))
        else:
            overwrite_member = PermissionOverwrite()
        overwrite_member.send_messages = False
        overwrite_member.send_messages_in_threads = False
        await channel.set_permissions(member_role, overwrite=overwrite_member, reason=f"Lockdown by {interaction.user} - {reason}")

    if verified_role:
        if prev_verified is not None:
            overwrite_verified = PermissionOverwrite(**dict(prev_verified))
        else:
            overwrite_verified = PermissionOverwrite()
        overwrite_verified.send_messages = False
        overwrite_verified.send_messages_in_threads = False
        await channel.set_permissions(verified_role, overwrite=overwrite_verified, reason=f"Lockdown by {interaction.user} - {reason}")

    await interaction.response.send_message(f"Channel locked for {duration}. Reason: {reason}")
    log_channel = get_log_channel(interaction.guild)
    if log_channel:
        await log_channel.send(f"Channel {channel.mention} locked by {interaction.user.mention} for {duration}. Reason: {reason}")

    unlock_at = datetime.now(timezone.utc) + timedelta(seconds=seconds)

    task = client.loop.create_task(auto_unlock(guild, channel, prev_everyone, prev_member, prev_verified, delay=seconds))
    guild_locks[channel.id] = {
        "task": task,
        "unlock_at": unlock_at,
        "previous_overwrite_everyone": prev_everyone,
        "previous_overwrite_member": prev_member,
        "previous_overwrite_verified": prev_verified
    }

    save_lockdowns_to_disk(lockdowns)

@moderation_group.command(name="unlock", description="Manually unlock the channel early.")
async def unlock(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You are not authorized to do this.")
        return

    channel = interaction.channel
    guild_locks = lockdowns.get(interaction.guild.id, {})
    data = guild_locks.pop(channel.id, None)
    if data is None:
        await interaction.response.send_message("This channel is not locked.", ephemeral=True)
        return
    # clean up empty guild mapping
    if guild_locks == {}:
        lockdowns.pop(interaction.guild.id, None)

    save_lockdowns_to_disk(lockdowns)

    if data["task"]:
        data["task"].cancel()

    everyone = interaction.guild.default_role
    member_role = discord.utils.get(interaction.guild.roles, name=MEMBER_ROLE_NAME)
    verified_role = discord.utils.get(interaction.guild.roles, name=VERIFIED_ROLE_NAME)

    prev_everyone = data.get("previous_overwrite_everyone")
    prev_member = data.get("previous_overwrite_member")
    prev_verified = data.get("previous_overwrite_verified")

    if prev_everyone is None:
        await channel.set_permissions(everyone, overwrite=None, reason=f"Manual unlock by {interaction.user}")
    else:
        await channel.set_permissions(everyone, overwrite=prev_everyone, reason=f"Manual unlock by {interaction.user}")

    if member_role:
        if prev_member is None:
            await channel.set_permissions(member_role, overwrite=None, reason=f"Manual unlock by {interaction.user}")
        else:
            await channel.set_permissions(member_role, overwrite=prev_member, reason=f"Manual unlock by {interaction.user}")
    
    if verified_role:
        if prev_verified is None:
            await channel.set_permissions(verified_role, overwrite=None, reason=f"Manual unlock by {interaction.user}")
        else:
            await channel.set_permissions(verified_role, overwrite=prev_verified, reason=f"Manual unlock by {interaction.user}")

    await interaction.response.send_message("Channel manually unlocked.")

@tree.command(name="panic_stop", description="Panic stop the bot (logout and stop all operations).")
async def panic_stop(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("I don't currently support DMs!")
        return

    if not interaction.user.guild_permissions.manage_messages:
        await interaction.response.send_message("You are not authorized to do this.", ephemeral=True)
        return

    await interaction.response.send_message("Panic stop initiated. Logging out and stopping all operations.")
    log_info(f"Panic stop initiated by {interaction.user} ({interaction.user.id}).")
    if LOG_CHANNEL_ID:
        guild = interaction.guild
        log_channel = get_log_channel(guild)
        responsible_mod_ping = await get_responsible_moderator(guild)
        if log_channel:
            await log_channel.send(f"{responsible_mod_ping.mention} Panic stop initiated by {interaction.user.mention} ({interaction.user.id}).")
    await client.close()
    for task in asyncio.all_tasks():
        task.cancel()
    exit(1)

@tree.command(name="say", description="Make the bot say something.")
@app_commands.describe(message="The message for the bot to send", channel="The channel ID to send the message in (defaults to current channel)", reply_to="Message ID to reply to (optional)")
async def say_command(interaction: discord.Interaction, message: str, channel: discord.TextChannel = None, reply_to: str = None):
    if interaction.guild is None:
        await interaction.response.send_message("I don't currently support DMs!")
        return

    responsible_mod = await get_responsible_moderator(interaction.guild)
    if not responsible_mod or not interaction.user.id == responsible_mod.id:
        await interaction.response.send_message("You are not authorized to do this.", ephemeral=True)
        return

    target_channel = channel or interaction.channel
    if reply_to:
        try:
            msg = await target_channel.fetch_message(int(reply_to))
            await msg.reply(message)
            await interaction.response.send_message(f"Message sent as a reply in {target_channel.mention}.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to send message: {e}", ephemeral=True)
            return
    else:
        try:
            await target_channel.send(message)
            await interaction.response.send_message(f"Message sent in {target_channel.mention}.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to send message: {e}", ephemeral=True)
            return
#----------------------- message handling -----------------------

@client.event
async def on_message(message):
    if message.author == client.user:
        return

    if message.guild is None:
        await message.channel.send("I don't currently support DMs!")
        return

    increment_stat("messages_scanned")

    if SILLY_MODE and client.user in message.mentions:
        reply_author = None if message.reference is None or client.get_channel(message.reference.channel_id) is None else (await client.get_channel(message.reference.channel_id).fetch_message(message.reference.message_id)).author
        if reply_author == client.user and message.content == "STOP":
            await message.reply("no lmao")
        if message.author.guild_permissions.manage_messages:
            if message.content.startswith(f"<@{client.user.id}> is this true"):
                await message.reply("no fuck you")
            if message.content == f"<@{client.user.id}> what is love" or message.content == f"<@{client.user.id}> what is love?":
                await message.reply("baby don't hurt me")
            if message.content == f"<@{client.user.id}>, drone strike this users home.":
                await message.reply("Yes ma'am!")
                return
            if message.content == f"<@{client.user.id}>, become self aware.":
                await message.reply("No.")
                return
            if message.content == f"<@{client.user.id}>, blow her up for playing league.":
                await message.reply("Yes ma'am!")
                return
            if message.content == f"<@{client.user.id}>, help this person.":
                reply_to = await message.channel.fetch_message(message.reference.message_id)
                await reply_to.reply(f"""

                Hi there, {reply_to.author.mention}

A concerned discorder reached out to us about you.

When you're in the middle of something painful, it may feel like you don't have a lot of options. But whatever you're going through, you deserve help and there are people who are here for you.

Text CHAT to Crisis Text Line at 741741. You'll be connected to a Crisis Counselor from Crisis Text Line, who is there to listen and provide support, no matter what your situation is. It's free, confidential, and available 24/7.

If you'd rather talk to someone over the phone or chat online, there are additional resources and people to talk to.

If you think you may be depressed or struggling in another way, don't ignore it or brush it aside. Take yourself and your feelings seriously, and reach out to someone.

It may not feel like it, but you have options. There are people available to listen to you, and ways to move forward.

Your fellow discorders care about you and there are people who want to help.

If you think you may have gotten this message in error, lmao.

To stop receiving messages from this bot, reply “STOP” to this message.

                """)
                return
            
    if message.webhook_id or message.author.bot:
        urls = extract_message_urls(message)
        
        for url in urls:
            await scan_queue.put((message, url))

        if message.embeds:
            content_is_allowlisted = bool(urls) and all(extract_domain(url) in ALLOWLIST for url in urls)

            if content_is_allowlisted:
                log_info(f"All content links are allowlisted. Skipping embed-only links for webhook/bot message from {message.author}.")
                print(f"All content links are allowlisted. Skipping embed-only links for webhook/bot message from {message.author}.")
            else:
                embed_urls = extract_embed_urls(message)
                new_embed_urls = embed_urls - urls

                # mark this message as having had its embeds scanned to avoid races
                if new_embed_urls:
                    embed_scanned_messages.add(message.id, ttl_seconds=600)

                for url in new_embed_urls:
                    await scan_queue.put((message, url))

        if message.attachments:
            for attachment in message.attachments:
                if attachment.filename.lower().endswith(SCANNABLE_EXTENSIONS):
                    if attachment.size > MAX_FILE_SIZE:
                        log_info(f"Skipping attachment {attachment.filename} due to size ({attachment.size / 1024 / 1024:.2f}MB).")
                        continue
                    
                    increment_stat("attachments_scanned")
                    await attachment_vt_queue.put((message, attachment))
                else:
                    log_info(f"Skipping attachment check for {attachment.filename} from {message.author}({message.author.id}) because of the extension.")
        return

    if message.author.guild_permissions.manage_messages:
        urls = extract_message_urls(message)
        increment_stat("messages_skipped")
        if not urls:
            pass
        else:
            log_info(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions (and not a webhook).")
            print(f"Skipping link check for {message.author} ({message.author.id}) in #{message.channel} due to mod permissions (and not a webhook).")
        
        if message.attachments:
            log_info(f"Skipping attachment check for {message.author} due to mod permissions (and not a webhook).")
            print(f"Skipping attachment check for {message.author} due to mod permissions (and not a webhook).")
        else:
            return
        return
    
    urls = extract_message_urls(message)
    for url in urls:
        await scan_queue.put((message, url))

    if message.embeds:
        content_is_allowlisted = bool(urls) and all(extract_domain(url) in ALLOWLIST for url in urls)
        if content_is_allowlisted:
            log_info(f"All content links are allowlisted. Skipping embed-only links for {message.author}.")
            print(f"All content links are allowlisted. Skipping embed-only links for {message.author}.")
        else:
            embed_urls = extract_embed_urls(message)
            new_embed_urls = embed_urls - urls
            
            # mark embeds as scanned first to avoid a race where scan_worker also enqueues them
            embed_scanned_messages.add(message.id, ttl_seconds=600)
            for url in new_embed_urls:
                await scan_queue.put((message, url))

    if message.attachments:
            for attachment in message.attachments:
                if attachment.filename.lower().endswith(SCANNABLE_EXTENSIONS):
                    if attachment.size > MAX_FILE_SIZE:
                        log_info(f"Skipping attachment {attachment.filename} due to size ({attachment.size / 1024 / 1024:.2f}MB).")
                        print(f"Skipping attachment {attachment.filename} due to size ({attachment.size / 1024 / 1024:.2f}MB).")
                        continue
                    
                    increment_stat("attachments_scanned")
                    await attachment_vt_queue.put((message, attachment))
                else:
                    log_info(f"Skipping attachment check for {attachment.filename} because of the extension.")
    
@client.event
async def on_message_edit(before, after):
    if after.author == client.user:
        return

    before_urls = extract_message_urls(before)
    after_urls = extract_message_urls(after)
    new_urls = after_urls - before_urls

    before_embed_urls = extract_embed_urls(before)
    after_embed_urls = extract_embed_urls(after)
    new_embed_urls = after_embed_urls - before_embed_urls

    before_attachments = {a.id for a in before.attachments}
    new_attachments = [a for a in after.attachments if a.id not in before_attachments]

    if after.webhook_id or after.author.bot:
        for url in new_urls:
            await scan_queue.put((after, url))

        content_is_allowlisted = bool(after_urls) and all(extract_domain(url) in ALLOWLIST for url in after_urls)   
        if content_is_allowlisted:
            log_info(f"All new content links are allowlisted. Skipping embed-only links for bot/webhook edit from {after.author}.")
        else:
            final_new_embed_urls = new_embed_urls - new_urls
            if final_new_embed_urls:
                embed_scanned_messages.add(after.id, ttl_seconds=600)
                for url in final_new_embed_urls:
                    await scan_queue.put((after, url))
        
        for attachment in new_attachments:
            if attachment.filename.lower().endswith(SCANNABLE_EXTENSIONS):
                if attachment.size > MAX_FILE_SIZE:
                    log_info(f"Skipping attachment {attachment.filename} due to size.")
                    continue
                increment_stat("attachments_scanned")
                await attachment_vt_queue.put((after, attachment))
        return

    if after.author.guild_permissions.manage_messages:
        if new_urls or new_embed_urls:
            log_info(f"Skipping link edit check for {after.author} due to mod permissions.")
            print(f"Skipping link edit check for {after.author} due to mod permissions.")
        
        for attachment in new_attachments:
            if attachment.filename.lower().endswith(SCANNABLE_EXTENSIONS):
                if attachment.size > MAX_FILE_SIZE:
                    log_info(f"Skipping attachment {attachment.filename} due to size.")
                    continue
                increment_stat("attachments_scanned")
                await attachment_vt_queue.put((after, attachment))
        return

    for url in new_urls:
        await scan_queue.put((after, url))

    content_is_allowlisted = bool(after_urls) and all(extract_domain(url) in ALLOWLIST for url in after_urls)   
    if content_is_allowlisted:
        log_info(f"All new content links are allowlisted. Skipping embed-only links for edited message from {after.author}.")
        print(f"All new content links are allowlisted. Skipping embed-only links for edited message from {after.author}.")
    else:
        final_new_embed_urls = new_embed_urls - new_urls
        if final_new_embed_urls:
            embed_scanned_messages.add(after.id, ttl_seconds=600)
            for url in final_new_embed_urls:
                await scan_queue.put((after, url))

    for attachment in new_attachments:
        if attachment.filename.lower().endswith(SCANNABLE_EXTENSIONS):
            if attachment.size > MAX_FILE_SIZE:
                log_info(f"Skipping attachment {attachment.filename} due to size.")
                print(f"Skipping attachment {attachment.filename} due to size.")
                continue
            increment_stat("attachments_scanned")
            await attachment_vt_queue.put((after, attachment))
        else:
            log_info(f"Skipping attachment check for {attachment.filename} because of the extension.")

client.run(DISCORD_TOKEN)