"""APScheduler-based digest scheduler — one job registered per topic."""

import logging
from typing import Callable, Dict, List

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from signalsage.digest.fetcher import fetch_topic

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
        watchlist: Dict,
        notifiers: List[Callable],
        default_schedule: str = "0 6 * * *",
        timezone: str = "UTC",
    ) -> None:
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.timezone = timezone
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

    async def _run_topic(self, topic: Dict) -> None:
        """Fetch, summarize, and notify for a single topic."""
        name = topic.get("name", "Unknown")
        logger.info("Running digest for topic: %s", name)

        try:
            fetched = await fetch_topic(
                topic.get("sources", []),
                self.summarizer.max_chars,
                timeout=15,
            )
            summary = await self.summarizer.summarize_topic(name, fetched)
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

    async def run_topic_now(self, topic_name: str) -> None:
        """Manually trigger a specific topic by name (for testing)."""
        job_id = "digest_" + topic_name.lower().replace(" ", "_")
        job = self._scheduler.get_job(job_id)
        if job is None:
            logger.error("No scheduled topic named '%s'", topic_name)
            return
        await job.func(*job.args)

    async def run_all_now(self) -> None:
        """Manually trigger all topics immediately (for testing)."""
        for job in self._scheduler.get_jobs():
            if job.id.startswith("digest_"):
                await job.func(*job.args)

    def start(self) -> None:
        self._scheduler.start()
        logger.info("Digest scheduler started (%d topic(s))", len(self._scheduler.get_jobs()))

    def shutdown(self) -> None:
        self._scheduler.shutdown(wait=False)
        logger.info("Digest scheduler stopped")
