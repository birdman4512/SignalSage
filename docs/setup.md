# SignalSage Setup Guide

## Prerequisites

- **Docker + Docker Compose** (recommended) — [docker.com/get-started](https://www.docker.com/get-started/)
- **Or:** Python 3.14+ for running locally without Docker
- At minimum, a **Slack** or **Discord** account with permission to add a bot

---

## 1. Clone and configure

```bash
git clone https://github.com/birdman4512/SignalSage.git
cd SignalSage

# Create your local .env from the template
cp .env.example .env
```

`config/config.yaml` and the digest files in `config/digests/` are committed and ready to edit directly. Edit `.env` with your tokens and keys (sections below explain how to get each one).

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
   | `reactions:read` | Receive 👍/👎 story feedback |
   | `reactions:write` | Pre-add 👍/👎 to each digest story |

### 2.4 Install to your workspace

1. Still in **OAuth & Permissions** → scroll to the top → **Install to Workspace** → **Allow**
2. Copy the `xoxb-...` **Bot User OAuth Token** → add to `.env`:
   ```
   SLACK_BOT_TOKEN=xoxb-...
   ```

### 2.5 Subscribe to message events

1. Left sidebar → **Event Subscriptions** → toggle **Enable Events** ON
2. Under **Subscribe to bot events** → **Add Bot User Event**, add:
   - `message.channels`
   - `message.groups`
   - `message.im`
   - `message.mpim`
   - `reaction_added` and `reaction_removed` (👍/👎 story feedback)
3. **Save Changes**

### 2.6 Create channels and invite the bot

Create (or use existing) Slack channels matching the `digest_channel` values in your `config/digests/` files, plus at least one channel for IOC monitoring. Then in **each channel** type:

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
3. Bot Permissions: tick `Read Messages/View Channels`, `Send Messages`, `Read Message History`, `Add Reactions`
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
| `!digest list` | Show all scheduled topics, tags, and next run time |
| `!digest <tag>` | Run topics matching a tag (e.g. `!digest cyber`, `!digest vuln`) |
| `!digest <name>` | Run a topic by partial name match (case-insensitive) |
| `!digest top <N>` | Override stories per digest this session (1–20, default 5) |
| `!digest help` | Show the command reference |

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

## 5. Gemini (digest summaries)

Digest summaries, borderline relevance checks and IOC assessments use Google's
Gemini API. The free tier is enough for this bot.

1. Open **[aistudio.google.com/apikey](https://aistudio.google.com/apikey)** and click **Create API key**.
2. Choose **Create API key in new project**. The project must have **no billing
   account linked**: a key in a billed project is on the paid (prepay) tier and
   fails with `402 ... prepayment credits are depleted`.
3. Put it in `.env`:
   ```
   GEMINI_API_KEY=...
   GEMINI_MODEL=gemini-flash-lite-latest
   ```

Without a key the bot still enriches IOCs; it just posts no digests. Free-tier
quotas are per model and change often (check your project in AI Studio), and
Google may use free-tier prompts to improve its products. The bot batches up to
8 articles per call and spaces calls 6 s apart to stay inside them.

---

## 6. Threat Intel API Keys

All threat-intel providers are optional. The bot runs with whichever keys you provide; providers that *require* a key are skipped when the key is blank, and optional-key providers fall back to unauthenticated rate limits.

| Provider | Key required? | Free tier | Sign up |
|---|---|---|---|
| **VirusTotal** | Yes | 500 req/day, 4/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **Shodan** | Yes | Very limited | [account.shodan.io](https://account.shodan.io/register) |
| **GreyNoise** | Optional | 100 req/day | [viz.greynoise.io](https://viz.greynoise.io/signup) |
| **AbuseIPDB** | Yes | 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **AlienVault OTX** | Optional | Unlimited | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup) |
| **URLhaus** | Yes (`ABUSECH_API_KEY`) | Free | [auth.abuse.ch](https://auth.abuse.ch/) |
| **ThreatFox** | Yes (`ABUSECH_API_KEY`) | Free (same key as URLhaus) | [auth.abuse.ch](https://auth.abuse.ch/) |
| **MalwareBazaar** | No | Free | automatic |
| **IPInfo** | Optional | 50k req/month | [ipinfo.io/signup](https://ipinfo.io/signup) |
| **CIRCL CVE** | No | Free | automatic |
| **URLScan** | Optional | Rate-limited | [urlscan.io/user/signup](https://urlscan.io/user/signup/) |

The `!osint` commands use these additional providers:

| Provider | Key required? | Notes | Sign up |
|---|---|---|---|
| **crt.sh** | No | Cert transparency for `!osint domain` | automatic |
| **WHOIS Age** | Optional (`WHOISXML_API_KEY`) | Falls back to free RDAP | [whoisxmlapi.com](https://whoisxmlapi.com/) |
| **CIRCL PDNS** | Yes (`CIRCL_PDNS_KEY`) | Format `user:password`. Used by `!osint domain` and `!osint ip`. | [circl.lu/services/passive-dns/](https://www.circl.lu/services/passive-dns/) |
| **HIBP** | Yes (`HIBP_API_KEY`) | ~$3.50/month. Used by `!osint email`. | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| **BGPView** | No | Used by `!osint asn` | automatic |

Add keys to your `.env` file:
```
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
ABUSECH_API_KEY=...
```

---

## 7. News digest configuration

Collection runs every 15 minutes, including quiet hours. Articles are persisted in SQLite before selection and summarization. The general news topics publish at 08:00, 12:00 and 16:00 Brisbane time; specialist topics keep their own schedules.

Configure personal interests under `digest.profile` and topic include/exclude keywords in `config/digests/`. Use weekday names in cron expressions: `mon-fri` avoids ambiguity because APScheduler's numeric weekdays start at Monday=0.

```yaml
name: "Vulnerability Alerts"
schedule: "15 7 * * mon-fri"
digest_channel: "#vuln-alerts"
keywords: ["CVE", "zero-day", "exploit"]
top_stories_count: 5
sources:
  - name: "CISA Advisories"
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml"
```

Each run posts one message per topic: numbered stories, each with a headline link, source and short summary, then a few headline-only extras. React with a story's number to rate it useful; removing the reaction withdraws the vote. Failed generations remain eligible; failed posts are queued and retried from the last acknowledged message. Empty digests are not posted.

Use `!digest status` for collection/delivery counts and `!digest feedback <article-id> useful|less` to adjust future source rankings. Keyword commands apply to all topics. `!digest top <N>` overrides per-topic counts for the current session.

Shortlisted podcast episodes are transcribed by Gemini (up to about an hour of audio); set `digest.transcribe_podcasts: false` to turn that off.

A topic's `lookback` is now an initial-import bound only. It never drops persisted pending articles; later polls inspect every available feed entry. Keep the writable `data/` volume when upgrading.

See [README](../README.md) for the profile schema, retry guarantees and urgent alert rules.

---

## 8. Run

### Option A — Docker (recommended for production)

```bash
docker compose up -d --build
docker compose logs -f signalsage
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

## 9. Verify it's working

**IOC enrichment:** Post an IP address in one of your monitored channels:
```
Checking this: 185.220.101.45
```
SignalSage should reply within a few seconds with threat intel results.

**Digest (trigger immediately without waiting for the cron):** Run `!digest` in any monitored channel to trigger all topics on-demand, or `!digest <tag>` for a specific topic (e.g. `!digest cyber`). Check `docker compose logs -f` to see summarisation progress.

---

## 10. Troubleshooting

**Slack bot doesn't respond to messages**
- Check that you invited the bot to the channel: `/invite @SignalSage`
- Verify `SLACK_APP_TOKEN` starts with `xapp-` and `SLACK_BOT_TOKEN` starts with `xoxb-`
- Check Event Subscriptions are saved in the Slack app settings

**Discord bot doesn't respond to messages**
- Verify **Message Content Intent** is enabled in the bot settings at discord.com/developers/applications → your app → Bot → Privileged Gateway Intents
- Confirm `DISCORD_BOT_TOKEN` in `.env` is correct and `platforms.discord.enabled: true` in `config/config.yaml`
- Check the bot has been invited to the server and has permission to read and send messages in the channel
- Channel IDs in `monitor_channels` must be integers (not strings): `- 1234567890123456789` not `- "1234567890123456789"`

**Digests don't post / Gemini errors in the logs**
- `402 ... prepayment credits are depleted`: the key is in a billed project. Create a new key in a project with no billing (see section 5).
- `Gemini free-tier quota exhausted`: the daily quota for that model is used up. Stories post as quoted excerpts until it resets; reduce topics/schedules or try another `GEMINI_MODEL`.
- `400 INVALID_ARGUMENT`: if you set `digest.gemini_thinking_budget`, remove it; Gemini 3 models reject it.
- `Digest summarizer not started`: `GEMINI_API_KEY` is empty.

**IOC not detected**
- Private IPs (192.168.x.x, 10.x.x.x) are intentionally filtered
- Common domains (google.com, github.com, etc.) are filtered as benign
- IOCs inside code blocks (`` `backticks` `` or ` ```fenced blocks``` `) are intentionally ignored
