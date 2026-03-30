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
| `SLACK_BOT_TOKEN` | Slack bot OAuth token (`xoxb-...`) |
| `SLACK_APP_TOKEN` | Slack app-level token for Socket Mode (`xapp-...`) |
| `DISCORD_BOT_TOKEN` | Discord bot token |
| `VT_API_KEY` | VirusTotal API key |
| `SHODAN_API_KEY` | Shodan API key |
| `GREYNOISE_API_KEY` | GreyNoise API key (optional, falls back to community API) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `OTX_API_KEY` | AlienVault OTX API key (optional, works unauthenticated) |
| `IPINFO_API_KEY` | IPInfo API key (optional, works unauthenticated) |
| `ANTHROPIC_API_KEY` | Anthropic API key (only needed when `digest.llm_provider: anthropic`) |

### `config/config.yaml`

Main configuration file. Uses `${ENV_VAR}` syntax for environment variable substitution. Key settings:

- `platforms.slack.enabled` — enable/disable Slack integration
- `platforms.slack.monitor_channels` — list of channel names (e.g. `["#security", "#ioc-feed"]`); empty = all channels
- `platforms.slack.digest_channel` — channel for daily digest (e.g. `"#daily-digest"`)
- `platforms.discord.enabled` — enable/disable Discord integration
- `platforms.discord.monitor_channels` — list of channel IDs (integers); empty = all channels
- `platforms.discord.digest_channel` — channel ID (integer) for daily digest
- `intel.max_iocs_per_message` — max IOCs to look up per message (default: 5)
- `intel.cache_ttl` — seconds to cache lookup results (default: 3600)
- `intel.timeout` — HTTP timeout per provider request in seconds (default: 10)
- `digest.llm_provider` — LLM backend: `"ollama"` (default) or `"anthropic"`
- `digest.anthropic_model` — Anthropic model ID (default: `"claude-haiku-4-5-20251001"`)
- `digest.anthropic_api_key` — Anthropic API key (or use `${ANTHROPIC_API_KEY}`)
- `digest.ollama_base_url` — Ollama endpoint (default: `"http://localhost:11434"`)
- `digest.ollama_model` — Ollama model to use (default: `"llama3.2"`)
- `digest.ollama_num_ctx` — Ollama context window tokens (default: 8192)
- `digest.max_chars_per_source` — max characters fetched per source before summarization (default: 3000)
- `digest.default_schedule` — fallback cron schedule for topics that don't define their own (default: `"0 6 * * *"` = 6 AM UTC)
- `digest.timezone` — timezone for the scheduler (default: `"UTC"`)
- `whisper.enabled` — enable Whisper audio transcription service
- `whisper.base_url` — Whisper service endpoint (default: `"http://whisper:8000"`)

### `config/watchlist.yaml`

Defines topics and sources for the daily digest. Each topic can have its own `schedule` (5-part cron expression) and `tags` list for bot command targeting. If `schedule` is omitted, falls back to `digest.default_schedule`. Supports RSS feeds (`.xml`, `.rss`, `.atom`) and regular HTML pages.

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
| `!digest list` | Show all scheduled topics and their tags |
| `!digest <tag>` | Run topics matching a tag (e.g. `!digest cyber`) |
| `!digest <name>` | Run a topic by partial name match (case-insensitive) |

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
    → post to notifiers (slack_bot.send_digest, discord_bot.send_digest)
```

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
| **URLhaus** | No key required | Completely free, no registration needed. |
| **URLScan** | No key required | Completely free public API. |
| **ThreatFox** | No key required | Completely free, no registration needed. |
| **MalwareBazaar** | No key required | Completely free, no registration needed. |
| **IPInfo** | 50,000 req/month (free) | Works without key up to rate limit. |
| **CIRCL CVE** | No key required | Completely free public API. |
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
    │   ├── fetcher.py       # RSS/web content fetcher
    │   └── summarizer.py    # LLM-based digest summarization
    └── bots/
        ├── commands.py      # !digest command parsing (shared by Slack + Discord)
        ├── formatter.py     # Platform-aware message formatting
        ├── slack.py         # Slack Socket Mode bot
        └── discord_bot.py   # Discord bot (discord.py v2)
```
