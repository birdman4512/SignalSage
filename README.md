# SignalSage

A self-hosted Slack and Discord bot for **automatic IOC enrichment** and **personalized news digests**, designed to work with small local models.

## IOC checks are still automatic

Post an IP, domain, URL, file hash, email, CVE or ASN in a monitored channel. SignalSage extracts indicators, queries the applicable intelligence providers, caches results, and posts an enriched report. An optional LLM assessment updates the report afterwards. `!osint` commands remain available.

The news pipeline reuses the same processor to enrich CVEs explicitly mentioned in shortlisted articles. It does not replace message-based IOC checks or send every news URL to every provider.

## News pipeline

```text
Collect feeds every 15 minutes, including overnight
  → persist individual articles and content revisions in SQLite
  → remove already queued/delivered articles for each destination
  → score against interests, products, geography and exclusions
  → ask the model about borderline relevance only
  → fetch shortlisted article text / optionally transcribe podcasts
  → enrich explicit CVEs using existing providers
  → generate and validate a short summary for each selected article
  → persist exact outgoing messages
  → deliver on schedule, acknowledge each message, retry failures
```

The four general news topics publish at **08:00, 12:00 and 16:00 Australia/Brisbane** (Saturday skips 08:00; Sunday is quiet all day), five stories each. Specialist topics keep their own schedules, and `urgent-alerts.yaml` posts exploited-vulnerability news as soon as it appears. Collection continues during quiet hours. Each run is **one message** per topic: numbered stories with a headline link, source and a one-to-two sentence summary, then an *Also* list of the next `headline_count` (default 5) confident matches as headline-only links. Those cost no model time, and once shown they count as delivered. React with a story's number (1️⃣–🔟) to rate it as useful; that adjusts source rankings. Slack needs the `reactions:read`/`reactions:write` scopes and the `reaction_added`/`reaction_removed` events; Discord needs the Add Reactions permission. Set `SEED_VOTE_REACTIONS=false` in `.env` (or `digest.seed_vote_reactions: false`) to stop the bot pre-adding the number reactions; users' own reactions still count.

## Start

1. Copy `.env.example` to `.env` and configure Slack/Discord credentials and optional provider keys. See [setup instructions](docs/setup.md).
2. Edit `config/config.yaml` and the topics in `config/digests/`.
3. Start the chosen backend:

```bash
docker compose --profile ollama up -d --build
docker compose logs -f
```

The default remains `gemma2:2b`. Ollama uses a fixed 4,096-token context, explicit temperature zero, one generation at a time, and short article responses. Oversized inputs fail instead of silently growing memory usage. Tune `article_chars` and `max_prompt_chars` together with `ollama_num_ctx` if needed.

Anthropic and CLI backends remain available through the existing configuration. Ollama is the default for lean unattended operation. Model changes should be tested against saved articles on the actual deployment hardware.

## Personalize

Put install-private settings, such as your interest profile, in `config/config.local.yaml`. It is gitignored and merged over `config/config.yaml`, so `git pull` and [auto-deploy](deploy/README.md) never conflict with it.

```yaml
digest:
  collection_minutes: 15
  default_schedule: "0 9,16 * * *"
  timezone: "Australia/Brisbane"
  top_stories_count: 5
  profile:
    minimum_score: 2.5
    topics: {ransomware: 3, "local LLM": 3}
    products: ["Linux"]          # replace with products you use
    geography: ["Brisbane"]     # optional
    sources: {"abc.net.au": 0.5}
    exclude: ["sponsored"]
```

Topic `keywords` add weighted interests; matches use word boundaries and phrases. A mention only in the excerpt receives less weight than a headline match. Borderline scores are checked by the model. Source trust and feedback adjust existing relevance; they cannot promote an unrelated story on their own. Topics can override profile fields with their own `profile` block.

Keyword commands work for both scheduled and urgent topics. YAML keywords seed the existing persistent runtime keyword store only once; subsequent edits use commands. Feedback adjusts source weights modestly and is saved per article and user. It is not an automatic claim to have learned all your interests.

```text
!digest                         run all topics now
!digest news                    run a topic by tag or name
!digest list                    show topic schedules
!digest top 3                   override story count for this session
!digest status                  article count, pending deliveries, source errors
!digest keywords news           show include/exclude keywords
!digest keywords news add "local LLM"
!digest keywords news exclude sponsored
!digest feedback <article-id> useful
!digest feedback <article-id> less   (or just react 👍 / 👎 on the story)
!osint ip 8.8.8.8
!osint domain example.com
!osint email user@example.com
!osint asn AS13335
!version                        version, commit and uptime of the running bot
```

For an immediate alert topic, explicitly configure `watch_mode: true` and `alert_keywords`, for example `["actively exploited"]`. It must pass both relevance selection and the alert rule. Quiet hours still apply. Ordinary news topics should use a cron schedule. See [the topic template](config/digests/template.yaml.example).

## Optional podcasts

Whisper is disabled and its container is excluded by default. To enable it:

```dotenv
COMPOSE_PROFILES=ollama,podcasts
WHISPER_ENABLED=true
```

Only shortlisted episodes are transcribed. Their transcript and summary are persisted, so subsequent deliveries do not repeat the work. With transcription disabled or unavailable, summaries are labelled as based on feed excerpts.

Resource needs, measured on a 4-core CPU-only host with `base.en`: a ~40-minute (38 MB) episode peaks Whisper at about 1.3 GB and takes roughly 20 minutes per CPU. The container is therefore given 2 GB and 2 CPUs; at 1 GB it is killed mid-transcription. Episodes over 80 MB (roughly two hours) are not transcribed and use their feed description instead. Transcription runs when an episode is shortlisted, so that topic's post can arrive 10–20 minutes after its scheduled time. A transcript is condensed to `article_chars` before summarizing: its opening (header, description, or intro) plus the passages that best match the episode title and the topic's keywords, kept verbatim.

A source can instead point at a show's published text transcript with `transcript_url` (with `{episode}` filled from `episode_pattern` matched against the item title). Security Now uses GRC's transcripts this way, so it is never sent to Whisper. Those transcripts appear a few days after an episode airs, so the episode is held for up to `digest.transcript_wait_days` (default 4) and then falls back to its show notes.

## Optional Reddit API

Subreddit sources work without credentials through RSS, but Reddit allows an unauthenticated IP about one request a minute. They are therefore fetched a minute apart and refreshed hourly. With an approved Reddit API app (about 100 requests a minute), set these in `.env` and restart:

```dotenv
REDDIT_CLIENT_ID=...
REDDIT_CLIENT_SECRET=...
REDDIT_USERNAME=your-reddit-username   # used in the required User-Agent
```

Reddit requires you to request access and receive explicit approval before using the API (see its Responsible Builder Policy). Create the app as type *script*; the bot uses application-only OAuth, so no redirect or user login is involved. The existing `/r/<name>/.rss` source URLs are mapped to API listings automatically, so the topic files don't change.

## Persistence and upgrades

Back up `data/`. Stop the bot before copying its SQLite files, or use SQLite's backup API for a consistent live database backup. The directory must be writable by the bot's container user (UID 10001 for the Ollama profile).

Article collection and each source's successful checkpoint commit together. Failed or empty generations are not delivery success. Exact rendered messages, article reservations and per-message acknowledgements survive restarts. Retries use exponential backoff and Slack's `Retry-After`. Canonical URLs strip tracking parameters; content hashes distinguish revisions; conservative title/content comparison reduces syndication duplicates before model calls. Delivery is tracked separately for each platform/channel.

Delivery is **at least once**: a process crash after Slack accepts a message but before the local acknowledgement commits can still cause a duplicate. Stable Slack `client_msg_id` values reduce this risk; they do not constitute an exactly-once guarantee.

On first upgrade the new article store starts with up to seven days of available feed content (`bootstrap_days`). Old `watch_seen.json` and headline history are not treated as proof of delivery because the old implementation saved them before delivery. An initial repeat is therefore possible. Existing keyword preferences are retained. A topic's explicit `lookback` now controls only its initial import; it never cuts off persisted pending articles or later recovery. Stories older than `max_article_age_days` (default 8) — by publish date, or collection date when a feed gives none — are never posted, so a quiet day cannot surface stale backlog.

No poller can recover entries a publisher has already removed from its feed. Collect often enough for busy sources. After initialization every available entry is inspected, including late or out-of-order publication dates. Completed/rejected history is pruned after `retention_days`; undelivered articles and feedback are retained.

## Evaluate and test

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check signalsage tests
ruff format --check signalsage tests
mypy signalsage --ignore-missing-imports

# Offline ranking check: no model calls, provider calls or Slack posts
python -m signalsage.digest.evaluate --output data/rules-eval.json

# Optional comparison against already installed local models
python -m signalsage.digest.evaluate --models gemma2:2b qwen3.5:4b --output data/model-eval.json
```

Replace or extend `tests/fixtures/news_eval.json` with articles you have labelled. The shipped dataset is synthetic and includes difficult examples to expose false positives and missed interests. Reports include precision/recall, response latency, validation failures, generation token metrics and samples for human factuality review. Optional memory sampling uses Ollama's reported model allocation, **not peak system RAM**. Use a host profiler to measure total memory.

Verbatim evidence validation helps catch malformed or ungrounded responses, but does not prove every generated claim. Review the saved summaries and expected/forbidden-term checks before selecting a model. The evaluation command never downloads models or sends messages.

## Operations and health

SignalSage exposes a private HTTP operations endpoint on port `8080` inside the
container. It is not published to the host by the supplied Compose file.

```text
GET /health/live   process liveness and uptime
GET /health/ready  readiness after configuration and components start
GET /metrics       article, outbox, source-error, and latest-run metrics as JSON
```

Set `LOG_FORMAT=json` for structured logs and `LOG_LEVEL` to control verbosity.
Platform connections are supervised independently and restart with bounded
exponential backoff.

Configuration is validated before network connections are opened. Invalid time
zones, cron expressions, numeric limits, source URLs, duplicate topic names,
missing platform credentials, and unsupported LLM backends stop startup with a
clear error.

SQLite migrations are transactional and recorded in `schema_version`. Back up
`data/` before upgrading. An older binary refuses to open a newer database.

Production dependencies are hash-locked in `requirements.lock`. Regenerate it
after intentionally changing `requirements.txt`:

```bash
uv pip compile requirements.txt --universal --python-version 3.14 \
  --generate-hashes --output-file requirements.lock
```
