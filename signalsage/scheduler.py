"""APScheduler-based digest scheduler — one job registered per topic."""

import logging
from collections.abc import Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from signalsage.digest.fetcher import fetch_topic, parse_lookback

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
    ) -> None:
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.timezone = timezone
        self.whisper_base_url = whisper_base_url
        self._scheduler = AsyncIOScheduler(timezone=timezone)

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

    async def _run_topic(self, topic: dict) -> None:
        """Fetch, summarize, and notify for a single topic."""
        name = topic.get("name", "Unknown")
        logger.info("Running digest for topic: %s", name)

        lookback = topic.get("lookback") or None
        lookback_seconds = parse_lookback(lookback)

        try:
            fetched = await fetch_topic(
                topic.get("sources", []),
                self.summarizer.max_chars,
                timeout=15,
                lookback_seconds=lookback_seconds,
                whisper_base_url=self.whisper_base_url,
            )
            summary = await self.summarizer.summarize_topic(name, fetched, lookback=lookback)
        except Exception as exc:
            logger.exception("Failed to generate digest for topic '%s': %s", name, exc)
            return

        header = f"📰 *Daily Digest: {name}*\n{'━' * 40}\n"
        message = header + summary
        # Per-topic channel override (None = use each bot's configured default)
        topic_channel = topic.get("digest_channel") or None

        for notify in self.notifiers:
            try:
                await notify(message, channel=topic_channel)
            except Exception as exc:
                logger.error(
                    "Notifier %s failed for topic '%s': %s",
                    getattr(notify, "__qualname__", repr(notify)),
                    name,
                    exc,
                )

    def get_topic_names(self) -> list[str]:
        """Return names of all scheduled digest topics."""
        return [name for name, _ in self.get_topics()]

    def get_topics(self) -> list[tuple[str, list[str]]]:
        """Return (name, tags) for all scheduled digest topics."""
        return [
            (job.args[0]["name"], job.args[0].get("tags", []))
            for job in self._scheduler.get_jobs()
            if job.id.startswith("digest_")
        ]

    async def run_topic_now(self, topic_query: str) -> bool:
        """Run a topic whose name or tags contain *topic_query* (case-insensitive).

        Returns True if a matching topic was found and triggered, False otherwise.
        """
        query = topic_query.strip().lower()
        for job in self._scheduler.get_jobs():
            if not job.id.startswith("digest_"):
                continue
            topic = job.args[0]
            name: str = topic["name"]
            tags: list[str] = [t.lower() for t in topic.get("tags", [])]
            if query in name.lower() or name.lower() in query or query in tags:
                logger.info("Triggering on-demand digest for topic '%s'", name)
                await job.func(*job.args)
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
