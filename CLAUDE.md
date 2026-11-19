# CLAUDE.md

Guidance for Claude Code when working in this repository. User-facing docs: [README.md](README.md) (features, config, operations) and [docs/setup.md](docs/setup.md) (Slack/Discord/API key setup). Deployment: [deploy/README.md](deploy/README.md).

## What it is

An async Python 3.14 bot for Slack (and optionally Discord) that:

1. **Enriches IOCs** posted in channels (IPs, domains, URLs, hashes, emails, CVEs, ASNs) by querying threat-intel providers in parallel, then adds a short Gemini assessment. `!osint` runs deeper lookups.
2. **Posts personalized news digests**: collects feeds into SQLite every 15 minutes, scores articles against an interest profile, and summarizes the selected ones with Google Gemini (the only LLM backend).

Runs as one Docker container. Production is a GCP e2-micro (1 GB RAM) that auto-deploys `main`.

## Commands

```bash
pip install --require-hashes -r requirements.lock && pip install -r requirements-dev.txt
pytest                                   # all tests; no live network calls (respx mocks)
ruff check signalsage tests && ruff format --check signalsage tests
mypy signalsage --ignore-missing-imports
python -m signalsage.main                # run locally (needs .env)
docker compose up -d --build             # run in Docker
```

CI (`.github/workflows/ci.yml`, job **`Lint & Test`**) runs ruff, format check, mypy, pytest with a 55% coverage floor, and validates the shipped config; a separate job runs `pip-audit`. `docker.yml` builds the image and scans it. **Auto-deploy only ships commits whose `Lint & Test` check passed**, so keep that job name.

## Layout

```
signalsage/
  main.py          process wiring: config → providers → LLM → bots → scheduler → health server
  bootstrap.py     PROVIDERS registry + build_providers() + build_llm() (Gemini, or None without a key)
  config.py        YAML load with ${ENV:-default} substitution, *.local.yaml merge, validation
  scheduler.py     APScheduler: cron topics, watch-mode polling, collection, active-hours gate
  observability.py /health/live, /health/ready, /metrics on :8080; logging setup
  ioc/             extractor.py (regex + defang), processor.py (parallel lookups + TTL cache)
  intel/           base.py (BaseProvider, IntelResult) + one file per provider
  llm/             base.py (BaseLLM, LLMRateLimitError), gemini.py (REST via httpx, no SDK)
  digest/
    collection.py  feed/page/Reddit collection, article text fetch (SSRF-checked redirects)
    fetcher.py     feed parsing, HTML extraction, podcast audio download for transcription
    store.py       SQLite store (articles, decisions, outbox, deliveries, feedback); migrations.py
    ranking.py     score_article(), canonical URLs, near-duplicate detection
    pipeline.py    DigestPipeline: collect → rank → judge → prepare → summarize → enqueue → flush
    summarizer.py  prompts + validation; single and batched (judge_relevance_batch, summarize_batch)
    transcripts.py published show transcripts; watch.py runtime keyword store; reddit.py API client
  bots/            slack.py, discord_bot.py, commands.py (shared !digest/!osint), formatter.py, auth.py
config/config.yaml            committed defaults;  config/config.local.yaml  install-private (gitignored)
config/digests/*.yaml         one topic per file;  *.local.yaml              private topics (gitignored)
deploy/autodeploy.sh          cron pull-deploy gated on CI
```

## How the digest works

- **Collection** runs every `collection_minutes`, independent of posting schedules. Each source's checkpoint commits with its articles. A fresh store imports only `bootstrap_days` of history.
- **Selection** (`pipeline.publish`): candidates not yet reserved for a destination are scored (`ranking.score_article`). Headline matches score full weight, excerpt matches half. A topic with no keywords is "open" (base score 3). At most `top_n * 2` distinct stories form the window; those below `minimum_score` go to Gemini in **one batched relevance call**.
- **Summaries**: selected articles get full text (`prepare`), then **one batched summary call** (`summarizer.batch_size`, default 8). Every summary must return its exact `art_id` and a **verbatim evidence quote** from its own source text (`_check_summary`); failures get one batched retry, then fall back to a quoted excerpt (`excerpt_summary`). On `LLMRateLimitError` (daily quota gone) stories post as quoted excerpts, uncached.
- **Delivery**: one combined message per topic per destination is persisted in the outbox before sending and acknowledged per message; delivery is at-least-once.
- Store methods are called by name through `store.acall("method", ...)` (thread offload), so static dead-code tools report them as unused. They aren't.
- Keywords in topic YAML seed `data/watch_keywords.json` **once**; afterwards `!digest keywords ...` edits the runtime store. Editing YAML keywords on a running install has no effect.

## Gemini specifics

- `gemini.py` posts to `generateContent` with `x-goog-api-key`. JSON mode uses `responseMimeType` + `responseJsonSchema`; `minLength`/`maxLength` are stripped from schemas before sending.
- Calls are serialized and spaced `gemini_min_interval` (6 s). A 429 with a short `retryDelay` is retried; otherwise `LLMRateLimitError`.
- Do **not** send `thinkingConfig.thinkingBudget` by default: Gemini 3 models reject it (400). Thinking tokens also count against `maxOutputTokens`. Measured: thinking adds no quality for this workload.
- The free key must come from a project **without billing**; a billed project's key returns 402 (prepay).
- `GeminiLLM.transcribe(path, mime)` transcribes shortlisted podcast audio: resumable Files API upload → poll until `ACTIVE` → `generateContent` with `fileData` → delete the file. Audio costs ~32 tokens/s, so `fetcher._MAX_AUDIO_BYTES` (64 MB ≈ 1 h) keeps one episode under the free per-minute token limit.

## Conventions

- Dependencies: pin in `requirements.txt` (also feeds `pyproject.toml`), then regenerate the hash lock:
  `uv pip compile requirements.txt --universal --python-version 3.14 --generate-hashes --output-file requirements.lock`.
  Dependabot pip PRs don't update the lock; regenerate it on those branches.
- New intel provider: subclass `BaseProvider` in `signalsage/intel/` (`name`, `supported_types`, `requires_key`, `async lookup(ioc) -> IntelResult`), add it to `PROVIDERS` in `bootstrap.py`, add its key under `intel.providers` in `config.yaml` and to `.env.example`.
- New topic: copy `config/digests/template.yaml.example`; restart to load. Cron weekdays: use names (`mon-fri`); APScheduler numbers Monday as 0.
- Never take URLs, IDs or titles from model output; Python owns them.
- Tests mock HTTP with `respx`; pipeline tests use a `SimpleNamespace` summarizer, and batch mode is only used when `batch_size > 1`.
