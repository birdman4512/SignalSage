# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## What is SignalSage?

SignalSage is a fully async, Docker-based threat intelligence bot that connects to **Slack** and **Discord**. It:

1. **Monitors messages** for Indicators of Compromise (IOCs) — IP addresses, domains, URLs, file hashes, email addresses, and CVEs.
2. **Enriches IOCs** in real-time by querying multiple threat intelligence APIs in parallel.
3. **Posts enriched results** back to the same channel with risk ratings, summaries, and links.
4. **Runs a scheduled LLM-powered news digest** by fetching configured RSS/web sources and summarizing them with a configurable LLM backend (Ollama or Anthropic Claude).

---

## Build and Run

### Docker (recommended)

```bash
# Build and start
docker-compose up -d --build

# Follow logs
docker-compose logs -f

# Stop
docker-compose down
```

### Development (without Docker)

```bash
# Create virtualenv
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and populate environment variables
cp .env.example .env
# Edit .env with your API keys

# Run
python -m signalsage.main
```

---

## Configuration

### Environment Variables (`.env`)

Copy `.env.example` to `.env` and fill in your credentials:

| Variable | Description |
|---|---|
| `SLACK_ENABLED` | `true`/`false` — enables the Slack integration (default `true`) |
| `SLACK_BOT_TOKEN` | Slack bot OAuth token (`xoxb-...`) |
| `SLACK_APP_TOKEN` | Slack app-level token for Socket Mode (`xapp-...`) |
| `SLACK_DIGEST_CHANNEL` | Default Slack digest channel name (e.g. `daily-digest`) used when a topic doesn't specify its own |
| `DISCORD_ENABLED` | `true`/`false` — enables the Discord integration (default `false`) |
| `DISCORD_BOT_TOKEN` | Discord bot token |
| `DISCORD_DIGEST_CHANNEL` | Default Discord digest channel ID (integer) |
| `VT_API_KEY` | VirusTotal API key |
| `SHODAN_API_KEY` | Shodan API key |
| `GREYNOISE_API_KEY` | GreyNoise API key (optional, falls back to community API) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `OTX_API_KEY` | AlienVault OTX API key (optional, works unauthenticated) |
| `IPINFO_API_KEY` | IPInfo API key (optional, works unauthenticated) |
| `ABUSECH_API_KEY` | abuse.ch API key — required for both URLhaus and ThreatFox (free at https://auth.abuse.ch) |
| `HIBP_API_KEY` | Have I Been Pwned API key — https://haveibeenpwned.com/API/Key |
| `WHOISXML_API_KEY` | WhoisXML API key (optional — falls back to free RDAP without key) |
| `CIRCL_PDNS_KEY` | CIRCL Passive DNS credentials as `user:password` (free at https://www.circl.lu/services/passive-dns/) |
| `LLM_PROVIDER` | `ollama` (default) or `anthropic` |
| `OLLAMA_BASE_URL` | Ollama endpoint URL (default `http://localhost:11434`; use `http://ollama:11434` for the bundled Docker service) |
| `OLLAMA_MODEL` | Ollama model to use (e.g. `gemma2:2b`) |
| `ANTHROPIC_API_KEY` | Anthropic API key (only needed when `digest.llm_provider: anthropic`) |

### `config/config.yaml`

Main configuration file. Uses `${ENV_VAR}` syntax for environment variable substitution. Key settings:

- `platforms.slack.enabled` — enable/disable Slack integration
- `platforms.slack.monitor_channels` — list of channel names (e.g. `["#security", "#ioc-feed"]`); empty = all channels
- `platforms.slack.digest_channel` — channel for daily digest (e.g. `"#daily-digest"`)
- `platforms.discord.enabled` — enable/disable Discord integration
- `platforms.discord.monitor_channels` — list of channel IDs (integers); empty = all channels
- `platforms.discord.digest_channel` — channel ID (integer) for daily digest
- `platforms.slack.command_allowlist` — list of Slack user IDs (e.g. `["U01234ABCD"]`) allowed to run `!digest` / `!osint`. Empty = anyone in a monitored channel. IOC enrichment is always automatic and is NOT gated by this allowlist.
- `platforms.discord.command_allowlist` — list of Discord user IDs (integers) allowed to run `!digest` / `!osint`. Empty = anyone in a monitored channel.
- `auth.command_cooldown_seconds` — per-user cooldown in seconds applied across both platforms. `0` disables (default: 30).
- `intel.max_iocs_per_message` — max IOCs to look up per message (default: 5)
- `intel.cache_ttl` — seconds to cache lookup results (default: 3600)
- `intel.timeout` — HTTP timeout per provider request in seconds (default: 10)
- `digest.llm_provider` — LLM backend: `"ollama"` (default) or `"anthropic"`
- `digest.anthropic_model` — Anthropic model ID (default: `"claude-haiku-4-5-20251001"`)
- `digest.anthropic_api_key` — Anthropic API key (or use `${ANTHROPIC_API_KEY}`)
- `digest.ollama_base_url` — Ollama endpoint (default: `"http://localhost:11434"`)
- `digest.ollama_model` — Ollama model to use (default: `"gemma2:2b"`)
- `digest.ollama_num_ctx` — Ollama context window tokens (default: 16384)
- `digest.ollama_timeout` — seconds to wait for an Ollama response (default: 1800; raise for slow CPU-only hardware)
- `digest.max_chars_per_source` — max characters fetched per source before summarization (default: 3000)
- `digest.max_total_chars_per_topic` — total prompt budget per topic across all sources (default: 20000)
- `digest.data_dir` — path used for digest history and source-health JSON (default: `"data"`; persisted in a Docker volume)
- `digest.lookback_buffer_hours` — buffer added to the auto-derived lookback when a topic omits an explicit `lookback`. The scheduler computes the lookback **per run** as the elapsed time between the two most recent scheduled fires + this buffer (default: 2). Examples for buffer=2: `0 5,11,17,23 * * *` → 8h every run (6h gap). `0 6 * * mon-fri` → 26h Tue–Fri but 74h on Monday (covers Fri→Mon over the weekend). `0 6 * * wed` → 170h (weekly). Topics with an explicit `lookback` in `watchlist.yaml` always win. Newly added topics that haven't fired yet fall back to the smallest *future* gap.
- `digest.default_schedule` — fallback cron schedule for topics that don't define their own (default: `"0 6 * * *"`, interpreted in `digest.timezone`)
- `digest.timezone` — timezone for the scheduler. Code default: `"UTC"`. Shipped `config.yaml` value: `"Australia/Brisbane"`.
- `digest.top_stories_count` — how many top stories are shown with a full summary; the rest appear as headline+link only (default: 10, adjustable at runtime with `!digest top <N>`). Individual topics can override this with `top_stories_count` in `watchlist.yaml`.
- `digest.interest_topics` — optional list of keywords (e.g. `["ransomware", "zero-day", "CISA"]`) passed to the LLM to help rank the most relevant stories higher
- `whisper.enabled` — enable Whisper audio transcription service
- `whisper.base_url` — Whisper service endpoint (default: `"http://whisper:8000"`)

### `config/watchlist.yaml`

Defines topics and sources for the daily digest. Each topic can have its own `schedule` (5-part cron expression), `tags` list for bot command targeting, and `top_stories_count` to override the global story card limit for that topic. If `schedule` is omitted, falls back to `digest.default_schedule`. Supports RSS feeds (`.xml`, `.rss`, `.atom`) and regular HTML pages.

```yaml
topics:
  - name: "Cybersecurity News"
    schedule: "0 6 * * *"     # 6am daily
    tags: ["cyber"]
    sources:
      - name: "Krebs on Security"
        url: "https://krebsonsecurity.com/feed/"

  - name: "Vulnerability Alerts"
    schedule: "0 7 * * 1-5"   # 7am weekdays
    tags: ["vuln"]
    sources: [...]
```

Both files are committed to the repository and can be edited directly.

---

## Slack App Setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app **"From scratch"**.
2. Under **Socket Mode**, enable Socket Mode and generate an **App-Level Token** with the `connections:write` scope. Set this as `SLACK_APP_TOKEN`.
3. Under **OAuth & Permissions**, add these **Bot Token Scopes**:
   - `channels:history` — read public channel messages
   - `channels:read` — list channels
   - `chat:write` — post messages
   - `groups:history` — read private channel messages
   - `im:history` — read DM messages
   - `mpim:history` — read group DM messages
4. Install the app to your workspace and copy the **Bot User OAuth Token** as `SLACK_BOT_TOKEN`.
5. Under **Event Subscriptions**, enable events and subscribe to **Bot Events**: `message.channels`, `message.groups`, `message.im`, `message.mpim`.
6. Invite the bot to channels: `/invite @SignalSage`

---

## Discord Bot Setup

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications) and create a new application.
2. Under **Bot**, click **Add Bot**.
3. Enable **Message Content Intent** under **Privileged Gateway Intents** (required to read message content).
4. Under **OAuth2 > URL Generator**, select scopes: `bot`, and permissions: `Read Messages/View Channels`, `Send Messages`, `Read Message History`.
5. Copy the generated URL, open in browser, and invite the bot to your server.
6. Copy the **Bot Token** as `DISCORD_BOT_TOKEN`.
7. Set `platforms.discord.enabled: true` in `config/config.yaml`.
8. Set `platforms.discord.monitor_channels` to a list of channel IDs (right-click channel > Copy ID with Developer Mode on), or leave empty for all channels.

---

## Bot Commands

Both Slack and Discord support the `!` command prefix (or `@SignalSage` mention on Slack):

| Command | Description |
|---|---|
| `!digest` | Run all digest topics immediately |
| `!digest list` | Show all scheduled topics, tags, and next run time |
| `!digest <tag>` | Run topics matching a tag (e.g. `!digest cyber`, `!digest vuln`) |
| `!digest <name>` | Run a topic by partial name match (case-insensitive) |
| `!digest top <N>` | Set how many top stories get full summaries this session (1–20, default 10) |
| `!digest help` | Show the command reference |
| `!help` | Show the command reference (shortcut) |
| `!osint email <address>` | Have I Been Pwned breach check for an email address |
| `!osint domain <domain>` | crt.sh cert transparency + WHOIS age + passive DNS |
| `!osint ip <address>` | CIRCL passive DNS for an IP address |
| `!osint asn <AS1234>` | BGPView ASN lookup (prefixes, IP ranges, org info) |

IOC enrichment is automatic — no command needed. Command parsing lives in `bots/commands.py` and is shared by both bot implementations.

---

## Architecture Overview

### IOC Extraction Pipeline

```
Message text
    → strip code blocks
    → regex extraction (CVE, URL, email, IPv4, IPv6, hashes, domains)
    → defang handling ([.] → ., hxxp → http)
    → private IP filtering
    → benign domain filtering
    → deduplication
    → cap at max_iocs_per_message
```

### Intel Lookup Pipeline

```
IOC list
    → TTLCache check (1-hour cache)
    → find applicable providers by IOCType
    → asyncio.gather() all providers in parallel
    → collect IntelResult objects
    → store in cache
    → format with formatter.py
    → post to channel
```

### Digest Pipeline

```
APScheduler registers one cron job per topic (using each topic's own schedule)
    → DigestScheduler._run_topic(topic) fires independently per topic
    → DigestSummarizer.summarize_topic(name, sources)
        → fetch_topic() for each topic (concurrent)
            → fetch_source() per URL
                → feedparser for RSS/Atom feeds
                → BeautifulSoup for HTML pages
        → BaseLLM.complete() — via OllamaLLM or AnthropicLLM
            LLM returns JSON with:
              "overview"  — 3-5 sentence narrative paragraph across all sources
              "items"     — up to 20 stories sorted by importance, each with
                            headline, 3-5 sentence summary, severity, icon, url
        → _postprocess_summary(): cross-topic dedup + trend classification
    → post to notifiers (slack_bot.send_digest, discord_bot.send_digest)
        → Message 1: topic header + overview + source coverage footer
        → Messages 2..N+1: one card per top story — headline, full summary, source host
                          (e.g. "reddit.com"), Read More link. Severity drives the embed colour
                          on Discord but is no longer printed as a "Medium" badge on the card.
        → Message N+2: remaining stories as a compact list, each shown as
                          "• <icon> headline · source.com"
```

The number of top stories `N` is set by `digest.top_stories_count` in `config.yaml` (default 10) and can be changed at runtime with `!digest top <N>`. Individual topics can override this with `top_stories_count` in `watchlist.yaml` (e.g. `top_stories_count: 5` on a Cybersecurity topic). Interest keywords in `digest.interest_topics` are injected into the LLM prompt to influence ranking.

### LLM Abstraction

`signalsage/llm/base.py` defines `BaseLLM` with a single `async complete(system, user, max_tokens) -> str` method. Two backends are provided:

- **`OllamaLLM`** — calls a locally-running Ollama instance (default). Requires Ollama installed and a model pulled (e.g. `ollama pull llama3.2`).
- **`AnthropicLLM`** — calls the Anthropic API. Requires `ANTHROPIC_API_KEY`.

The active backend is selected by `digest.llm_provider` in `config.yaml`. If the LLM fails to initialize, the digest scheduler is skipped entirely (bot still runs for IOC enrichment).

---

## Adding a New Intel Provider

1. Create a new file in `signalsage/intel/`, e.g. `signalsage/intel/myprovider.py`.
2. Extend `BaseProvider`:

```python
from signalsage.intel.base import BaseProvider, IntelResult
from signalsage.ioc.models import IOC, IOCType

class MyProvider(BaseProvider):
    name = "MyProvider"
    supported_types = [IOCType.IPV4, IOCType.DOMAIN]
    requires_key = True  # or False

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        # Call your API using httpx
        ...
        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=True,
            score=85,
            summary="Detected as malicious",
            report_url="https://...",
        )
```

3. Register in `signalsage/main.py`:

```python
from signalsage.intel.myprovider import MyProvider
add_provider(MyProvider, 'myprovider')
```

4. Add to `config/config.yaml` under `intel.providers`:

```yaml
myprovider:
  enabled: true
  api_key: ${MY_PROVIDER_API_KEY}
```

5. Add `MY_PROVIDER_API_KEY` to `.env.example` and `.env`.

---

## Adding a New LLM Backend

1. Create `signalsage/llm/mybackend.py` extending `BaseLLM`:

```python
from signalsage.llm.base import BaseLLM

class MyBackendLLM(BaseLLM):
    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        ...
```

2. Add a branch in `signalsage/main.py` under the `llm_provider` selection block.
3. Add any new config keys under `digest` in `config/config.yaml`.

---

## Adding a New Watchlist Topic

Edit `config/watchlist.yaml` and add a new entry under `topics`:

```yaml
topics:
  - name: "My New Topic"
    tags: ["mytag"]
    sources:
      - name: "Source Name"
        url: "https://example.com/feed.xml"
      - name: "Another Source"
        url: "https://example.com/blog"
```

RSS/Atom feeds (`.xml`, `.rss`, `.atom`) are automatically detected and parsed with feedparser. Other URLs are fetched as HTML and parsed with BeautifulSoup.

---

## API Rate Limits and Provider Notes

| Provider | Free Tier | Notes |
|---|---|---|
| **VirusTotal** | 4 req/min, 500/day | Public API key required. Premium increases limits significantly. |
| **Shodan** | 1 query credit/lookup | Paid API. Free account has very limited credits. |
| **GreyNoise** | 100 req/day (community) | Works without key at reduced rate. Premium API has higher limits. |
| **AbuseIPDB** | 1,000 req/day | Free registration required. |
| **AlienVault OTX** | Unlimited (free) | Works unauthenticated but with stricter rate limits. Free registration recommended. |
| **URLhaus** | Unlimited | Free `ABUSECH_API_KEY` required (sign up at https://auth.abuse.ch). |
| **URLScan** | No key required | Completely free public API. |
| **ThreatFox** | Unlimited | Free `ABUSECH_API_KEY` required (same key as URLhaus). |
| **MalwareBazaar** | No key required | Completely free, no registration needed. |
| **IPInfo** | 50,000 req/month (free) | Works without key up to rate limit. |
| **CIRCL CVE** | No key required | Completely free public API. |
| **crt.sh** | No key required | Certificate transparency — domain lookups. |
| **WHOIS Age** | No key required | Uses free RDAP. Optional `WHOISXML_API_KEY` lifts rate limits. |
| **CIRCL PDNS** | Free account | `CIRCL_PDNS_KEY` as `user:password`. Passive DNS — domain and IP lookups. |
| **HIBP** | Paid key required | Have I Been Pwned — email breach lookups. ~$3.50/month. |
| **BGPView** | No key required | Free ASN/prefix lookups via `!osint asn`. |
| **Ollama** | Free (local) | Requires local GPU/CPU. Default digest LLM. Pull models with `ollama pull <model>`. |
| **Anthropic Claude** | Pay per token | Optional digest LLM. ~$0.25/MTok input, $1.25/MTok output for Haiku. |

### Caching

All intel lookup results are cached for `intel.cache_ttl` seconds (default 1 hour) using `cachetools.TTLCache`. This means repeated lookups of the same IOC within the TTL window will return cached results instantly without consuming API quota.

---

## Testing

```bash
# Install dev dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run all tests
pytest

# Run a single test file
pytest tests/test_extractor.py -v

# Run a specific test
pytest tests/test_extractor.py::test_ipv4_defanged_brackets -v
```

Tests use `pytest-asyncio` (all async tests run automatically with `asyncio_mode = "auto"` in `pyproject.toml`). HTTP calls are mocked with `respx` where needed. No live API calls are made in tests.

### CI/CD

- **`.github/workflows/ci.yml`** — runs on every push/PR to `main`: ruff lint + format check, mypy type check, pytest.
- **`.github/workflows/docker.yml`** — builds the Docker image on every push/PR; uses GitHub Actions layer cache. Uncomment the push section to publish to GHCR on merge to `main`.

---

## Project Structure

```
SignalSage/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml           # pytest + ruff + mypy config
├── .env.example
├── config/
│   ├── config.yaml          # Main config
│   └── watchlist.yaml       # Digest sources and schedules
├── tests/
└── signalsage/
    ├── main.py              # Entry point, wires everything together
    ├── config.py            # Config loading + env var substitution
    ├── scheduler.py         # APScheduler-based digest scheduler
    ├── ioc/
    │   ├── models.py        # IOC and IOCType dataclasses/enums
    │   ├── extractor.py     # Regex-based IOC extraction with defanging
    │   └── processor.py     # Orchestrates extraction + lookup + caching
    ├── intel/
    │   ├── base.py          # BaseProvider ABC + IntelResult dataclass
    │   └── *.py             # One file per provider
    ├── llm/
    │   ├── base.py          # BaseLLM ABC
    │   ├── anthropic_llm.py # Anthropic API backend
    │   └── ollama.py        # Ollama local backend (default)
    ├── digest/
    │   ├── fetcher.py       # RSS/web/audio content fetcher
    │   ├── history.py       # Persistent digest history + source-health tracking
    │   └── summarizer.py    # LLM-based digest summarization
    └── bots/
        ├── commands.py      # !digest command parsing (shared by Slack + Discord)
        ├── formatter.py     # Platform-aware message formatting
        ├── slack.py         # Slack Socket Mode bot
        └── discord_bot.py   # Discord bot (discord.py v2)
```
