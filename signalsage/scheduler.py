"""APScheduler-based digest scheduler — one job registered per topic."""

import json
import logging
import re
import time
from collections.abc import Callable
from datetime import date

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from signalsage.digest.fetcher import fetch_topic, parse_lookback
from signalsage.digest.history import DigestHistory, _headline_hash

logger = logging.getLogger(__name__)


def _parse_cron(schedule: str, timezone: str) -> CronTrigger:
    parts = schedule.split()
    if len(parts) != 5:
        raise ValueError(
            f"Invalid cron schedule '{schedule}'. Expected 5 parts: "
            "minute hour day month day_of_week"
        )
    return CronTrigger(
        minute=parts[0],
        hour=parts[1],
        day=parts[2],
        month=parts[3],
        day_of_week=parts[4],
        timezone=timezone,
    )


def _postprocess_summary(
    summary: str,
    topic: str,
    history: DigestHistory,
    session_hashes: set[str],
) -> tuple[str, dict]:
    """
    Parse the LLM JSON, apply deduplication + trend classification, re-serialise.

    Returns (processed_summary, extra_meta) where extra_meta contains:
      - deduped_count: items removed by cross-topic session dedup
      - coverage_confidence: extracted from LLM output
    """
    extra: dict = {"deduped_count": 0, "coverage_confidence": None}

    try:
        text = summary.strip()
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return summary, extra

    if not isinstance(parsed, dict) or "items" not in parsed:
        return summary, extra

    # Extract coverage_confidence
    extra["coverage_confidence"] = parsed.get("coverage_confidence") or None

    items: list[dict] = [i for i in parsed.get("items", []) if isinstance(i, dict)]

    # ── Feature 5: cross-topic session deduplication ─────────────────────────
    deduped: list[dict] = []
    for item in items:
        h = _headline_hash(item.get("headline", ""))
        if h in session_hashes:
            logger.info(
                "Deduped cross-topic item in '%s': %s", topic, item.get("headline", "")[:60]
            )
            extra["deduped_count"] += 1
        else:
            deduped.append(item)
    items = deduped

    # Add all this topic's hashes to the session set
    for item in items:
        session_hashes.add(_headline_hash(item.get("headline", "")))

    # ── Feature 2: trend classification ─────────────────────────────────────
    trend_map = history.classify_items(topic, items)
    for item in items:
        h = _headline_hash(item.get("headline", ""))
        item["trend"] = trend_map.get(h, "new")

    # Persist items to history for future trend detection
    history.record_items(topic, items)

    # ── Icon fallback — ensure no item has an empty icon ─────────────────────
    for item in items:
        if not str(item.get("icon") or "").strip():
            item["icon"] = "📰"

    parsed["items"] = items
    return json.dumps(parsed, ensure_ascii=False), extra


class DigestScheduler:
    """Schedules one independent cron job per watchlist topic."""

    def __init__(
        self,
        summarizer,
        watchlist: dict,
        notifiers: list[Callable],
        default_schedule: str = "0 6 * * *",
        timezone: str = "UTC",
        whisper_base_url: str | None = None,
        data_dir: str = "data",
    ) -> None:
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.timezone = timezone
        self.whisper_base_url = whisper_base_url
        self._scheduler = AsyncIOScheduler(timezone=timezone)
        self._history = DigestHistory(data_dir=data_dir)
        self._session_hashes: set[str] = set()
        self._session_date: str = date.today().isoformat()

        topics = watchlist.get("topics", [])
        if not topics:
            logger.warning("Watchlist has no topics — digest scheduler idle")
            return

        for topic in topics:
            name = topic.get("name", "Unnamed")
            schedule = topic.get("schedule") or default_schedule
            job_id = "digest_" + name.lower().replace(" ", "_")

            try:
                trigger = _parse_cron(schedule, timezone)
            except ValueError as exc:
                logger.error("Skipping topic '%s': %s", name, exc)
                continue

            self._scheduler.add_job(
                self._run_topic,
                trigger,
                args=[topic],
                id=job_id,
                replace_existing=True,
            )
            logger.info("Scheduled topic '%s' — cron '%s' (%s)", name, schedule, timezone)

    def _reset_session_if_new_day(self) -> None:
        today = date.today().isoformat()
        if today != self._session_date:
            self._session_hashes.clear()
            self._session_date = today
            logger.info("New day — cross-topic dedup session reset")

    async def _run_topic(self, topic: dict, progress=None) -> None:
        """Fetch, summarize, and notify for a single topic.

        Args:
            progress: Optional async callable(str) for on-demand status updates.
                      Not used for scheduled runs — only wired up by run_topic_now.
        """
        self._reset_session_if_new_day()
        name = topic.get("name", "Unknown")
        logger.info("Running digest for topic: %s", name)

        lookback = topic.get("lookback") or None
        lookback_seconds = parse_lookback(lookback)
        sources = topic.get("sources", [])

        try:
            if progress:
                await progress(f"📡 Fetching {len(sources)} source(s) for *{name}*…")
            fetched = await fetch_topic(
                sources,
                self.summarizer.max_chars,
                timeout=15,
                lookback_seconds=lookback_seconds,
                whisper_base_url=self.whisper_base_url,
            )
            sources_ok = sum(1 for s in fetched if s.get("content", "").strip())
            total_chars = sum(len(s.get("content", "")) for s in fetched)
            if progress:
                size_hint = (
                    f"~{total_chars // 1000}k chars"
                    if total_chars >= 1000
                    else f"{total_chars} chars"
                )
                eta = self._history.estimate_llm_seconds(total_chars)
                if eta is not None:
                    eta_str = f"~{max(1, round(eta))}s" if eta < 90 else f"~{round(eta / 60)}m"
                    time_hint = f", ETA {eta_str}"
                else:
                    time_hint = " — this may take a minute"
                await progress(
                    f"🤖 Summarizing {sources_ok}/{len(fetched)} source(s)"
                    f" ({size_hint}{time_hint})…"
                )
            t0 = time.monotonic()
            summary = await self.summarizer.summarize_topic(name, fetched, lookback=lookback)
            self._history.record_llm_timing(total_chars, time.monotonic() - t0)
        except Exception as exc:
            logger.exception("Failed to generate digest for topic '%s': %s", name, exc)
            return

        # ── Source metadata ──────────────────────────────────────────────────
        empty_sources = [s["name"] for s in fetched if not s.get("content", "").strip()]
        if empty_sources:
            logger.warning(
                "Topic '%s': %d source(s) returned no content: %s",
                name,
                len(empty_sources),
                ", ".join(empty_sources),
            )

        # ── Feature 6: record source health, check chronic failures ─────────
        source_results = {s["name"]: bool(s.get("content", "").strip()) for s in fetched}
        self._history.record_source_results(source_results)
        chronically_failing = self._history.get_chronically_failing_sources(consecutive_days=3)
        # Only report failures that belong to this topic's sources
        topic_source_names = {s.get("name", "") for s in topic.get("sources", [])}
        topic_chronic = [s for s in chronically_failing if s in topic_source_names]
        if topic_chronic:
            logger.warning(
                "Topic '%s': sources failing for 3+ days: %s", name, ", ".join(topic_chronic)
            )

        # ── Features 2 & 5: dedup + trend classification ─────────────────────
        summary, extra_meta = _postprocess_summary(
            summary, name, self._history, self._session_hashes
        )
        if extra_meta["deduped_count"]:
            logger.info(
                "Topic '%s': removed %d cross-topic duplicate(s)",
                name,
                extra_meta["deduped_count"],
            )

        # Collect image URLs configured on individual sources
        images = [s["image_url"] for s in fetched if s.get("image_url")]

        meta = {
            "sources_total": len(fetched),
            "sources_ok": len(fetched) - len(empty_sources),
            "empty_sources": empty_sources,
            "chronically_failing": topic_chronic,
            "deduped_count": extra_meta["deduped_count"],
            "coverage_confidence": extra_meta["coverage_confidence"],
            "images": images,
        }

        # Per-topic channel override (None = use each bot's configured default)
        topic_channel = topic.get("digest_channel") or None

        for notify in self.notifiers:
            try:
                await notify(name, summary, lookback=lookback, channel=topic_channel, meta=meta)
            except Exception as exc:
                logger.error(
                    "Notifier %s failed for topic '%s': %s",
                    getattr(notify, "__qualname__", repr(notify)),
                    name,
                    exc,
                )

    def get_topic_names(self) -> list[str]:
        """Return names of all scheduled digest topics."""
        return [name for name, _tags, _next in self.get_topics()]

    def get_topics(self) -> list[tuple[str, list[str], object]]:
        """Return (name, tags, next_run_time) for all scheduled digest topics."""
        return [
            (job.args[0]["name"], job.args[0].get("tags", []), getattr(job, "next_run_time", None))
            for job in self._scheduler.get_jobs()
            if job.id.startswith("digest_")
        ]

    async def run_topic_now(self, topic_query: str, progress=None) -> bool:
        """Run a topic whose name or tags contain *topic_query* (case-insensitive).

        Exact tag matches take priority over partial name matches so that e.g.
        ``!digest news`` runs the topic tagged ``news`` rather than the first
        topic whose name happens to contain the word "news".

        Args:
            progress: Optional async callable(str) forwarded to _run_topic for
                      stage status updates.

        Returns True if a matching topic was found and triggered, False otherwise.
        """
        query = topic_query.strip().lower()
        jobs = [j for j in self._scheduler.get_jobs() if j.id.startswith("digest_")]

        # Pass 1: exact tag match
        for job in jobs:
            topic = job.args[0]
            tags = [t.lower() for t in topic.get("tags", [])]
            if query in tags:
                logger.info("Triggering on-demand digest for topic '%s'", topic["name"])
                await self._run_topic(topic, progress=progress)
                return True

        # Pass 2: partial name match
        for job in jobs:
            topic = job.args[0]
            name = topic["name"].lower()
            if query in name or name in query:
                logger.info("Triggering on-demand digest for topic '%s'", topic["name"])
                await self._run_topic(topic, progress=progress)
                return True

        logger.warning("No topic matching query '%s'", topic_query)
        return False

    async def run_all_now(self) -> None:
        """Trigger all digest topics immediately."""
        for job in self._scheduler.get_jobs():
            if job.id.startswith("digest_"):
                logger.info("Triggering on-demand digest for topic '%s'", job.args[0]["name"])
                await job.func(*job.args)

    def start(self) -> None:
        self._scheduler.start()
        logger.info("Digest scheduler started (%d topic(s))", len(self._scheduler.get_jobs()))

    def shutdown(self) -> None:
        self._scheduler.shutdown(wait=False)
        logger.info("Digest scheduler stopped")
