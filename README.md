# Link Checker Discord Bot (Using VirusTotal API)

----------------------------------------
Features: 
- Auto-remove malicious links.  
- A whitelist and blacklist that can be manipulated from discord via thie `lc!` prefix.  
- Logging (on device and on discord)
----------------------------------------
Setting up:  
- Create bot via Discord Developer Portal
- Clone this repository
- Set up a `.env` file inside the folder, that includes your bot's token as `DISCORD_TOKEN=`, your VirusTotal api as `VT_API_KEY=` and a channel id for logging as `LOG_CHANNEL_ID=`  
- Set up a whitelist.txt and a blacklist.txt, with each line contatining one link (syntax: discord.com)  
- Run the python script. The bot will scan each message, immediately delete it if it's on the blacklist, don't touch it if it's on the whitelist, and scan it via VirusTotal if it's on neither of those. If the message contains a malicious link, it will be removed.  
----------------------------------------
Commands:
- "lc!whitelist add <domain>    - Add domain to whitelist"  
- "lc!whitelist remove <domain> - Remove domain from whitelist"  
- "lc!whitelist show            - Show whitelisted domains"  
- "lc!reload whitelist          - Reload whitelist from file"  
- "lc!blacklist add <domain>    - Add domain to blacklist"  
- "lc!blacklist remove <domain> - Remove domain from blacklist"  
- "lc!blacklist show            - Show blacklisted domains"  
- "lc!reload blacklist          - Reload blacklist from file"  
- "lc!help                      - Show help message"  
  