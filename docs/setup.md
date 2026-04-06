# SignalSage Setup Guide

## Prerequisites

- **Docker + Docker Compose** (recommended) — [docker.com/get-started](https://www.docker.com/get-started/)
- **Or:** Python 3.12+ for running locally without Docker
- At minimum, a **Slack** or **Discord** account with permission to add a bot

---

## 1. Clone and configure

```bash
git clone https://github.com/birdman4512/SignalSage.git
cd SignalSage

# Create your local config files from the committed templates
cp config/config.example.yaml config/config.yaml
cp config/watchlist.example.yaml config/watchlist.yaml
cp .env.example .env
```

Edit `.env` with your tokens and keys (sections below explain how to get each one).

---

## 2. Slack Setup

### 2.1 Create the app

1. Go to **[api.slack.com/apps](https://api.slack.com/apps)** → **Create New App** → **From scratch**
2. Name it `SignalSage`, select your workspace → **Create App**

### 2.2 Enable Socket Mode (no public URL required)

1. Left sidebar → **Socket Mode** → toggle **Enable Socket Mode** ON
2. Click **Generate** → name the token (e.g. `signalsage-socket`) → scope `connections:write` must be checked
3. Copy the `xapp-1-...` token → add to `.env`:
   ```
   SLACK_APP_TOKEN=xapp-1-...
   ```

### 2.3 Add Bot Scopes

1. Left sidebar → **OAuth & Permissions** → scroll to **Bot Token Scopes** → **Add an OAuth Scope**
2. Add each of the following:

   | Scope | Purpose |
   |---|---|
   | `channels:history` | Read messages in public channels |
   | `channels:read` | Resolve channel names |
   | `chat:write` | Post messages |
   | `groups:history` | Read messages in private channels |
   | `im:history` | Read direct messages |
   | `mpim:history` | Read group direct messages |

### 2.4 Install to your workspace

1. Still in **OAuth & Permissions** → scroll to the top → **Install to Workspace** → **Allow**
2. Copy the `xoxb-...` **Bot User OAuth Token** → add to `.env`:
   ```
   SLACK_BOT_TOKEN=xoxb-...
   ```

### 2.5 Subscribe to message events

1. Left sidebar → **Event Subscriptions** → toggle **Enable Events** ON
2. Under **Subscribe to bot events** → **Add Bot User Event**, add all four:
   - `message.channels`
   - `message.groups`
   - `message.im`
   - `message.mpim`
3. **Save Changes**

### 2.6 Create channels and invite the bot

Create (or use existing) Slack channels matching your `config/watchlist.yaml` `digest_channel` values, plus at least one channel for IOC monitoring. Then in **each channel** type:

```
/invite @SignalSage
```

### 2.7 Update config.yaml

Edit `config/config.yaml` and set:
```yaml
platforms:
  slack:
    enabled: true
    monitor_channels:
      - "#security-alerts"   # bot will watch this channel for IOCs
    digest_channel: "#daily-digest"   # fallback if a topic has no digest_channel
```

Leave `monitor_channels` empty (`[]`) to monitor every channel the bot is invited to.

---

## 3. Discord Setup (optional)

### 3.1 Create a bot

1. Go to **[discord.com/developers/applications](https://discord.com/developers/applications)** → **New Application** → name it `SignalSage`
2. Left sidebar → **Bot** → **Add Bot** → confirm
3. Under **Privileged Gateway Intents**, enable **Message Content Intent** (required to read message text)
4. Copy the **Bot Token** → add to `.env`:
   ```
   DISCORD_BOT_TOKEN=...
   ```

### 3.2 Invite the bot to your server

1. Left sidebar → **OAuth2** → **URL Generator**
2. Scopes: tick `bot`
3. Bot Permissions: tick `Read Messages/View Channels`, `Send Messages`, `Read Message History`
4. Copy the generated URL, open in browser, select your server → **Authorise**

### 3.3 Get channel IDs

Enable Developer Mode: **User Settings → Advanced → Developer Mode**. Then right-click any channel → **Copy Channel ID**.

### 3.4 Update config.yaml

```yaml
platforms:
  discord:
    enabled: true
    monitor_channels:
      - 1234567890123456789   # paste channel IDs as integers
    digest_channel: 1234567890123456789
```

---

## 4. Bot Commands

Both Slack and Discord use the `!` prefix. On Slack you can also mention the bot (`@SignalSage <command>`).

### Digest commands

| Command | Description |
|---|---|
| `!digest` | Run all digest topics immediately |
| `!digest list` | Show all scheduled topics and their tags |
| `!digest <tag>` | Run topics matching a tag (e.g. `!digest cyber`) |
| `!digest <name>` | Run a topic by partial name match (case-insensitive) |

### OSINT commands

| Command | Description |
|---|---|
| `!osint email <address>` | Have I Been Pwned breach check for an email |
| `!osint domain <domain>` | crt.sh cert transparency + WHOIS age + passive DNS |
| `!osint ip <address>` | CIRCL passive DNS lookup for an IP |
| `!osint asn <AS1234>` | BGPView ASN lookup (prefixes, IP ranges, org info) |

### Automatic IOC enrichment

No command needed — just post any indicator in a monitored channel and SignalSage will reply automatically:

```
Checking this IP: 185.220.101.45
Hash to look up: 44d88612fea8a8f36de82e1278abb02f
CVE to research: CVE-2024-12345
```

Supported indicator types: IPv4, IPv6, domains, URLs, MD5/SHA1/SHA256/SHA512 hashes, CVEs, ASNs, and email addresses.

> **Tip:** Defanged indicators work too — `185[.]220[.]101[.]45`, `hxxps://example[.]com`, etc.

---

## 6. LLM Setup (daily digest summarisation)

The digest uses a local LLM by default — **no API cost, runs on your own hardware**.

### Recommended models (low memory + CPU)

| Model | RAM | Notes |
|---|---|---|
| `gemma2:2b` | ~1.6 GB | **Best lean choice.** Google model, excellent English summarisation. |
| `llama3.2:3b` | ~2.0 GB | Meta's latest small model, well-rounded. |
| `qwen2.5:1.5b` | ~1.0 GB | Absolute minimum. Acceptable quality for simple summaries. |
| `phi3.5:mini` | ~2.3 GB | Microsoft model, strong instruction following. |

**Recommendation: start with `gemma2:2b`.**

### 6.1 Install Ollama

Download from **[ollama.com/download](https://ollama.com/download)** and install.
Ollama runs as a background service automatically after installation.

### 6.2 Pull your chosen model

```bash
ollama pull gemma2:2b
```

Verify it works:
```bash
ollama run gemma2:2b "Summarise this in one sentence: Researchers discovered a new ransomware strain targeting healthcare."
```

### 6.3 Configure SignalSage to use it

In `.env`:
```
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=gemma2:2b
```

### 6.4 Alternative: paid Claude API

If you prefer Anthropic Claude instead:
```
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

The default model is `claude-haiku-4-5-20251001` (cheapest Claude model, ~$0.01/day for typical digest use).

### 6.5 Docker Compose with bundled Ollama

To run Ollama inside Docker alongside SignalSage:

```bash
# Pull your model first (one-time)
docker-compose --profile ollama up -d ollama
docker exec ollama ollama pull gemma2:2b

# Then in .env, change the URL to the Docker service name:
# OLLAMA_BASE_URL=http://ollama:11434

# Start everything
docker-compose --profile ollama up -d
```

---

## 7. Threat Intel API Keys

All providers are optional. The bot runs with whichever keys you provide; providers without keys are automatically disabled.

| Provider | Key required? | Free tier | Sign up |
|---|---|---|---|
| **VirusTotal** | Yes | 500 req/day, 4/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **Shodan** | Yes | Very limited | [account.shodan.io](https://account.shodan.io/register) |
| **GreyNoise** | Optional | 100 req/day | [viz.greynoise.io](https://viz.greynoise.io/signup) |
| **AbuseIPDB** | Yes | 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **AlienVault OTX** | Optional | Unlimited | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup) |
| **URLhaus** | No | Free | automatic |
| **ThreatFox** | No | Free | automatic |
| **MalwareBazaar** | No | Free | automatic |
| **IPInfo** | Optional | 50k req/month | [ipinfo.io/signup](https://ipinfo.io/signup) |
| **CIRCL CVE** | No | Free | automatic |

Add keys to your `.env` file:
```
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
```

---

## 8. Daily Digest Configuration

Edit `config/watchlist.yaml` to configure your topics. Each topic:
- has its own cron **`schedule`**
- posts to its own Slack/Discord **`digest_channel`**
- pulls from a list of RSS feeds or web pages

```yaml
topics:
  - name: "Vulnerability Alerts"
    schedule: "0 7 * * 1-5"       # 7am weekdays
    digest_channel: "#vuln-alerts" # Slack channel name or Discord channel ID
    sources:
      - name: "CISA Advisories"
        url: "https://www.cisa.gov/cybersecurity-advisories/all.xml"
      - name: "My Company Blog"
        url: "https://example.com/blog"   # HTML pages work too
```

Cron format: `minute hour day-of-month month day-of-week`
Examples:
- `0 6 * * *` — 6am every day
- `0 7 * * 1-5` — 7am weekdays
- `0 8 * * 1` — 8am every Monday
- `0 */6 * * *` — every 6 hours

---

## 9. Run

### Option A — Docker (recommended for production)

```bash
docker-compose up -d --build
docker-compose logs -f signalsage
```

### Option B — Python directly (good for development/testing)

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

pip install -r requirements.txt
python -m signalsage.main
```

---

## 10. Verify it's working

**IOC enrichment:** Post an IP address in one of your monitored channels:
```
Checking this: 185.220.101.45
```
SignalSage should reply within a few seconds with threat intel results.

**Digest (trigger immediately without waiting for the cron):** You can test the digest by temporarily changing a topic's schedule to run in 1–2 minutes, or by adding a debug trigger. Check `docker-compose logs -f` to see the output.

---

## 11. Troubleshooting

**Slack bot doesn't respond to messages**
- Check that you invited the bot to the channel: `/invite @SignalSage`
- Verify `SLACK_APP_TOKEN` starts with `xapp-` and `SLACK_BOT_TOKEN` starts with `xoxb-`
- Check Event Subscriptions are saved in the Slack app settings

**Discord bot doesn't respond to messages**
- Verify **Message Content Intent** is enabled in the bot settings at discord.com/developers/applications → your app → Bot → Privileged Gateway Intents
- Confirm `DISCORD_BOT_TOKEN` in `.env` is correct and `platforms.discord.enabled: true` in `config/config.yaml`
- Check the bot has been invited to the server and has permission to read and send messages in the channel
- Channel IDs in `monitor_channels` must be integers (not strings): `- 1234567890123456789` not `- "1234567890123456789"`

**"Cannot connect to Ollama"**
- Verify Ollama is running: `curl http://localhost:11434/api/tags`
- Check `OLLAMA_BASE_URL` in `.env` — use `http://localhost:11434` for local, `http://ollama:11434` for Docker Compose

**"Model not found" from Ollama**
- Pull the model first: `ollama pull gemma2:2b`
- Check `OLLAMA_MODEL` in `.env` matches exactly

**IOC not detected**
- Private IPs (192.168.x.x, 10.x.x.x) are intentionally filtered
- Common domains (google.com, github.com, etc.) are filtered as benign
- IOCs inside code blocks (`` `backticks` `` or ` ```fenced blocks``` `) are intentionally ignored
