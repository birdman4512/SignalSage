# SignalSage

A self-hosted Slack and Discord bot for **automatic IOC enrichment** and **personalized news digests**, summarized with Google's free Gemini API. It fits on a 1 GB VM.

## IOC checks

Post an IP, domain, URL, file hash, email, CVE or ASN in a monitored channel. SignalSage extracts indicators, queries the applicable intelligence providers in parallel, caches results and posts an enriched report, followed by a short Gemini assessment. `!osint` commands do deeper lookups on demand.

The news pipeline reuses the same processor to enrich CVEs mentioned in shortlisted articles.

## News pipeline

```text
Collect feeds every 15 minutes, including overnight
  → persist individual articles and content revisions in SQLite
  → drop articles already queued/delivered to each destination
  → score against interests, products, geography and exclusions
  → ask Gemini about borderline relevance only (one batched call)
  → fetch shortlisted article text / transcribe shortlisted podcast episodes
  → enrich explicit CVEs using the IOC providers
  → summarize the selected articles (one batched call), validating each
  → persist exact outgoing messages, deliver on schedule, retry failures
```

Each run posts **one message** per topic: numbered stories with a headline link, source and a short summary, then an *Also* list of the next `headline_count` (default 5) confident matches as headline-only links (no model cost). React with a story's number (1️⃣–🔟) to rate it useful; that adjusts source rankings. Slack needs the `reactions:read`/`reactions:write` scopes and `reaction_added`/`reaction_removed` events; Discord needs Add Reactions. `SEED_VOTE_REACTIONS=false` stops the bot pre-adding the number reactions.

Every summary must quote its own article verbatim as evidence, or it is replaced by a quoted excerpt. If the free daily quota runs out, stories post as quoted excerpts rather than being held back.

## Start

1. Copy `.env.example` to `.env`: Slack/Discord tokens, a free [Gemini API key](https://aistudio.google.com/apikey) (create it in a project **without billing**), and any intel provider keys. See the [setup guide](docs/setup.md).
2. Edit `config/config.yaml` and the topics in `config/digests/`.
3. Start it:

```bash
docker compose up -d --build
docker compose logs -f
```

Without `GEMINI_API_KEY` the bot runs IOC enrichment only. Gemini calls are batched (8 articles per call) and spaced `gemini_min_interval` seconds apart (default 6) to stay inside the free tier's per-minute and per-day quotas. Free-tier quotas change often, and Google may use free-tier prompts to improve its products. For unattended hosting see [deploy/README.md](deploy/README.md).

## Personalize

Put install-private settings, such as your interest profile, in `config/config.local.yaml`, and private topics in `config/digests/*.local.yaml`. Both are gitignored and merged over the committed config, so `git pull` and auto-deploy never conflict with them.

```yaml
digest:
  profile:
    minimum_score: 2.5
    topics: {ransomware: 3, "amateur radio": 3, "space weather": 3}
    products: ["Linux"]          # products you use (weight 4)
    geography: ["Brisbane"]      # optional (weight 2)
    sources: {"abc.net.au": 0.5}
    exclude: ["sponsored"]
```

A headline match scores a term's full weight and an excerpt-only match half. Stories at or above `minimum_score` qualify on their own; lower-scoring matches go to Gemini for a relevance check. Source trust and feedback adjust relevance but cannot promote an unrelated story. Topic `keywords` add weight-3 interests; topics can override profile fields with their own `profile` block. A topic with no keywords takes every story from its sources.

YAML keywords seed the persistent keyword store once; later edits use commands:

```text
!digest                         run all topics now
!digest news                    run a topic by tag or name
!digest list                    show topic schedules
!digest top 3                   override story count for this session
!digest status                  article count, pending deliveries, source errors
!digest keywords news           show include/exclude keywords
!digest keywords news add "local LLM"
!digest keywords news exclude sponsored
!digest feedback <article-id> useful|less
!osint ip 8.8.8.8
!osint domain example.com
!osint email user@example.com
!osint asn AS13335
!version                        version, commit and uptime of the running bot
```

### Urgent stories

`digest.urgent` routes urgent stories from **every** topic to one channel (default `#general`) as soon as they're collected, while the rest wait for their digests. A story qualifies if it's from the last 24 hours, passes its topic's relevance selection, and contains an alert keyword: the global `digest.urgent.alert_keywords` plus the topic's own `alert_keywords` (e.g. Solar & Propagation adds severe geomagnetic storms and X-class flares). Digests skip anything already sent there. `max_per_day` (default 10, rolling 24 hours) caps the volume; beyond it, stories wait for their digest. A topic opts out with `urgent: false`. Quiet hours apply.

For a separate alert topic with its own feeds and poll interval, set `watch_mode: true` and `alert_keywords`; quiet hours apply unless `ignore_active_hours: true` (SEQ Weather Alerts posts around the clock). See [the topic template](config/digests/template.yaml.example).

## Podcasts

When a podcast episode is shortlisted, the bot downloads its audio and Gemini transcribes it (Files API upload, deleted straight after); a 30-minute episode takes about 15 seconds and no local RAM. Only shortlisted episodes are transcribed, and transcripts are cached. Episodes over 64 MB (about an hour, the free tier's per-minute token limit) use their feed description. Transcripts are condensed to `article_chars` (opening plus the passages that best match the title and topic keywords) before summarizing. Set `digest.transcribe_podcasts: false` to turn it off.

A source can instead point at a show's published transcript with `transcript_url` (`{episode}` filled from `episode_pattern`). Security Now uses GRC's transcripts this way; the episode is held up to `digest.transcript_wait_days` (default 4) for it.

## Sites without RSS

A source that points at an ordinary page is read as one story (its text), which suits status pages like the solar reports. For a page that *lists* reports, add `link_pattern`, a regex: each link on the page whose URL matches becomes its own story, titled with its link text. A date in the URL or link text (`20240415`, `2024-04-15`) becomes its publish date, so the first import skips old ones. Undated links are all imported once.

```yaml
  - name: "CVERC reports"
    url: "https://www.cverc.org.cn/"
    link_pattern: "/head/zhaiyao/news\\d{8}"
```

## Optional Reddit API

Subreddit sources work without credentials through RSS, fetched a minute apart and refreshed hourly. With an approved Reddit API app (type *script*; Reddit requires explicit approval under its Responsible Builder Policy), set `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET` and `REDDIT_USERNAME` in `.env`. Existing `/r/<name>/.rss` URLs map to API listings automatically.

## Persistence and delivery

Back up `data/` (stop the bot first, or use SQLite's backup API). It must be writable by the container user (UID 10001).

Collection and each source's checkpoint commit together. Exact rendered messages, article reservations and per-message acknowledgements survive restarts; retries use exponential backoff and Slack's `Retry-After`. Canonical URLs strip tracking parameters, content hashes distinguish revisions, and title/content comparison reduces syndication duplicates before model calls. Delivery is **at least once**: a crash between Slack accepting a message and the local acknowledgement can still duplicate it.

A fresh store imports up to `bootstrap_days` (7) of feed history; a topic's `lookback` only bounds that first import. Stories older than `max_article_age_days` (8) are never posted. Completed history is pruned after `retention_days`; undelivered articles and feedback are kept. No poller can recover entries a publisher has already removed from its feed.

## Operations

A private HTTP endpoint on port `8080` inside the container (not published to the host):

```text
GET /health/live   process liveness and uptime
GET /health/ready  readiness after configuration and components start
GET /metrics       article, outbox, source-error and latest-run metrics as JSON
```

Set `LOG_FORMAT=json` for structured logs and `LOG_LEVEL` for verbosity. Platform connections restart with bounded exponential backoff. Configuration (time zones, cron expressions, limits, source URLs, duplicate topics, platform credentials) is validated before any connection opens. SQLite migrations are transactional; an older binary refuses a newer database.

## Development

```bash
pip install --require-hashes -r requirements.lock && pip install -r requirements-dev.txt
pytest
ruff check signalsage tests && ruff format --check signalsage tests
mypy signalsage --ignore-missing-imports
```

`requirements.txt` holds the pinned dependencies (and feeds `pyproject.toml`); `requirements.lock` is the hash-locked install set. After changing `requirements.txt`:

```bash
uv pip compile requirements.txt --universal --python-version 3.14 \
  --generate-hashes --output-file requirements.lock
```
