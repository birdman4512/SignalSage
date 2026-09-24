"""APScheduler-based digest scheduler — one job registered per topic."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from datetime import time as dtime
from zoneinfo import ZoneInfo

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from signalsage.digest.pipeline import DigestPipeline
from signalsage.digest.store import ArticleStore
from signalsage.digest.watch import WatchKeywords

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


def _compute_auto_lookback(
    schedule: str,
    timezone: str,
    buffer_hours: float,
    active_hours: dict | None = None,
    _now: datetime | None = None,
) -> str:
    """Return a lookback string equal to the elapsed time between the two most
    recent scheduled fires of *schedule* that actually ran, plus
    *buffer_hours* of overhang.

    Computing the gap *per run* means weekday-only schedules naturally widen
    the lookback after a long off-period (e.g. Monday's run on a `mon-fri`
    cron looks back ~74h to cover Fri→Mon) while Tue–Fri runs stay tight
    (~26h). ``_now`` is only used by tests.

    When *active_hours* is set, fire times the quiet-hours gate would have
    skipped are excluded from the gap calculation — they never produced a
    post, so counting them would under-estimate how much content has piled
    up since the last run that actually happened. This is what makes the
    first run after quiet hours "catch up": e.g. a schedule with fires
    outside the active window at 23:00/05:00 and inside it at 11:00/17:00
    computes today's 11:00 run's gap back to yesterday's 17:00 run (the last
    one that actually posted), not the nominal 6h between adjacent cron
    fields.

    Falls back to the smallest *future* gap (also active-hours filtered) when
    there is no recent past fire in the lookback window (e.g. a newly-added
    topic that hasn't fired yet).
    """
    trigger = _parse_cron(schedule, timezone)
    now = _now or datetime.now(UTC)
    tzinfo = ZoneInfo(timezone)

    def _allowed(dt: datetime) -> bool:
        if not active_hours:
            return True
        local = dt.astimezone(tzinfo)
        return _within_active_hours(
            local,
            active_hours.get("weekday_start", "00:00"),
            active_hours.get("weekday_end", "23:59"),
            active_hours.get("weekend_start", "00:00"),
            active_hours.get("weekend_end", "23:59"),
        )

    # Walk forward from 14d ago, keeping only the two most recent fires <= now
    # that would actually run (i.e. inside active_hours). 14d covers
    # weekly/biweekly digest cadences. 20k iterations is a safety cap for
    # pathological schedules (e.g. every-minute crons that have no business
    # being a digest topic but shouldn't crash the bot if added).
    start = now - timedelta(days=14)
    last_two: list[datetime] = []
    prev: datetime | None = None
    for _ in range(20_000):
        nxt = trigger.get_next_fire_time(prev, start if prev is None else prev)
        if nxt is None or nxt > now:
            break
        prev = nxt
        if _allowed(nxt):
            last_two.append(nxt)
            if len(last_two) > 2:
                last_two.pop(0)

    if len(last_two) == 2:
        gap_seconds = (last_two[1] - last_two[0]).total_seconds()
        hours = max(1, int(round((gap_seconds + buffer_hours * 3600) / 3600)))
        return f"{hours}h"

    # No past fires (or only one) in the 14d window — fall back to smallest
    # forward gap so a newly-added topic still gets a sensible default. Walk
    # further than 6 raw fires since active-hours filtering may skip several
    # before finding two that count.
    fires: list[datetime] = []
    prev = None
    for _ in range(200):
        nxt = trigger.get_next_fire_time(prev, now if prev is None else prev)
        if nxt is None:
            break
        prev = nxt
        if _allowed(nxt):
            fires.append(nxt)
        if len(fires) >= 6:
            break
    if len(fires) < 2:
        return "25h"
    min_gap = min((fires[i + 1] - fires[i]).total_seconds() for i in range(len(fires) - 1))
    hours = max(1, int(round((min_gap + buffer_hours * 3600) / 3600)))
    return f"{hours}h"


def _parse_hhmm(value: str) -> dtime:
    hour, _, minute = value.strip().partition(":")
    return dtime(int(hour), int(minute or 0))


def _within_active_hours(
    now: datetime,
    weekday_start: str,
    weekday_end: str,
    weekend_start: str,
    weekend_end: str,
) -> bool:
    """Return True if *now* (a tz-aware local datetime) falls inside the
    configured active window — weekday window Mon-Fri, weekend window Sat-Sun.
    """
    is_weekend = now.weekday() >= 5  # Sat=5, Sun=6
    start_s, end_s = (weekend_start, weekend_end) if is_weekend else (weekday_start, weekday_end)
    start, end = _parse_hhmm(start_s), _parse_hhmm(end_s)
    return start <= now.time() < end


class DigestScheduler:
    """Collect continuously; publish on explicit schedules; retry durable outbox messages."""

    def __init__(
        self,
        summarizer,
        watchlist: dict,
        notifiers: list[Callable],
        default_schedule: str = "0 9,16 * * *",
        timezone: str = "UTC",
        whisper_base_url: str | None = None,
        data_dir: str = "data",
        top_stories_count: int = 5,
        lookback_buffer_hours: float = 2,
        watch_default_poll_minutes: int = 15,
        active_hours: dict | None = None,
        profile: dict | None = None,
        processor=None,
        pipeline_settings: dict | None = None,
    ):
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.timezone = timezone
        self.default_schedule = default_schedule
        self.lookback_buffer_hours = lookback_buffer_hours
        self.top_stories_count = top_stories_count
        self._top_override: int | None = None
        self.active_hours = active_hours
        self._tzinfo = ZoneInfo(timezone)
        self._scheduler = AsyncIOScheduler(
            timezone=timezone,
            executors={"default": AsyncIOExecutor()},
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600},
        )
        self._scheduler.add_listener(self._on_job_executed, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
        self._watch_keywords = WatchKeywords(data_dir=data_dir)
        self.store = ArticleStore(data_dir)
        self.pipeline = DigestPipeline(
            summarizer,
            notifiers,
            self.store,
            self._watch_keywords,
            profile=profile,
            processor=processor,
            whisper_base_url=whisper_base_url,
            settings=pipeline_settings,
        )
        self._topics = []
        for topic in watchlist.get("topics", []):
            name = topic.get("name", "Unnamed")
            self._watch_keywords.seed_defaults(
                name, topic.get("keywords") or [], topic.get("exclude_keywords") or []
            )
            try:
                if topic.get("watch_mode"):
                    trigger = IntervalTrigger(
                        minutes=max(
                            1, int(topic.get("poll_interval_minutes") or watch_default_poll_minutes)
                        )
                    )
                    func, job_prefix = self._run_watch_topic_scheduled, "watch_"
                else:
                    trigger = _parse_cron(topic.get("schedule") or default_schedule, timezone)
                    func, job_prefix = self._run_topic_scheduled, "digest_"
                self._scheduler.add_job(
                    func,
                    trigger,
                    args=[topic],
                    id=job_prefix + name.lower().replace(" ", "_"),
                    replace_existing=True,
                )
                self._topics.append(topic)
            except ValueError as exc:
                logger.error("Skipping topic '%s': %s", name, exc)
        if self._topics:
            interval = max(1, int((pipeline_settings or {}).get("collection_minutes", 15)))
            self._scheduler.add_job(
                self._collect_all,
                IntervalTrigger(minutes=interval),
                id="collect_articles",
                next_run_time=datetime.now(UTC),
            )
            self._scheduler.add_job(
                self._retry_delivery, IntervalTrigger(minutes=1), id="retry_delivery"
            )

    def _on_job_executed(self, event):
        if event.exception:
            logger.error("Digest job %s failed: %s", event.job_id, event.exception)

    def _in_active_hours(self) -> bool:
        if not self.active_hours:
            return True
        return _within_active_hours(
            datetime.now(self._tzinfo),
            self.active_hours.get("weekday_start", "00:00"),
            self.active_hours.get("weekday_end", "23:59"),
            self.active_hours.get("weekend_start", "00:00"),
            self.active_hours.get("weekend_end", "23:59"),
        )

    async def _collect_all(self):
        # Collection deliberately continues during quiet hours and while the LLM is busy.
        for topic in self._topics:
            try:
                await self.pipeline.collect(topic)
            except Exception:
                logger.exception("Collection failed for %s; checkpoint retained", topic["name"])
        self.store.prune(int(self.pipeline.settings.get("retention_days", 90)))

    async def _retry_delivery(self):
        if self._in_active_hours():
            await self.pipeline.flush(allowed=self._in_active_hours)

    async def _run_topic_scheduled(self, topic):
        if self._in_active_hours():
            await self._run_topic(topic, scheduled=True)

    async def _run_watch_topic_scheduled(self, topic):
        if self._in_active_hours():
            await self._run_watch_topic(topic, scheduled=True)

    async def _run_topic(self, topic, progress=None, override_channel=None, scheduled=False):
        if progress:
            await progress(f"Fetching articles for {topic['name']}...")
        try:
            await self.pipeline.collect(topic)
            if progress:
                await progress("Selecting and summarizing relevant articles...")
            await self.pipeline.publish(
                topic,
                self._top_n(topic),
                override_channel,
                progress,
                delivery_allowed=self._in_active_hours if scheduled else None,
            )
        except Exception:
            logger.exception("Digest failed for %s; articles retained for retry", topic["name"])
            if progress:
                await progress(
                    "Digest could not finish. Collected articles remain queued for retry."
                )

    async def _run_watch_topic(self, topic, progress=None, override_channel=None, scheduled=False):
        added = await self.pipeline.collect(topic)
        await self.pipeline.publish(
            topic,
            self._top_n(topic),
            override_channel,
            progress,
            urgent=True,
            delivery_allowed=self._in_active_hours if scheduled else None,
        )
        return bool(added)

    def _top_n(self, topic: dict) -> int:
        """The topic's own top_stories_count, else the (runtime-adjustable) global one."""
        if self._top_override is not None:
            return self._top_override
        topic_top_n = topic.get("top_stories_count")
        return max(
            1, min(20, int(topic_top_n) if topic_top_n is not None else self.top_stories_count)
        )

    def set_top_stories_count(self, n: int) -> None:
        """Update the number of top stories shown with full summaries (session only)."""
        self.top_stories_count = max(1, min(n, 20))
        self._top_override = self.top_stories_count
        logger.info("Top stories count set to %d", self.top_stories_count)

    def get_topic_names(self) -> list[str]:
        """Return names of all scheduled digest topics."""
        return [name for name, _tags, _next in self.get_topics()]

    def get_topics(self) -> list[tuple[str, list[str], object]]:
        """Return (name, tags, next_run_time) for all scheduled digest and watch-mode topics."""
        return [
            (job.args[0]["name"], job.args[0].get("tags", []), getattr(job, "next_run_time", None))
            for job in self._scheduler.get_jobs()
            if job.id.startswith("digest_") or job.id.startswith("watch_")
        ]

    async def run_topic_now(self, topic_query: str, progress=None, override_channel=None) -> bool:
        """Run a topic whose name or tags contain *topic_query* (case-insensitive).

        Exact tag matches take priority over partial name matches so that e.g.
        ``!digest news`` runs the topic tagged ``news`` rather than the first
        topic whose name happens to contain the word "news".

        Args:
            progress: Optional async callable(str) forwarded to _run_topic for
                      stage status updates.
            override_channel: Fallback channel passed from on-demand commands so
                              the digest appears in the channel where it was typed
                              when no digest_channel is configured.

        Returns True if a matching topic was found and triggered, False otherwise.
        """
        query = topic_query.strip().lower()
        jobs = [
            j
            for j in self._scheduler.get_jobs()
            if j.id.startswith("digest_") or j.id.startswith("watch_")
        ]

        async def _dispatch(job) -> None:
            topic = job.args[0]
            logger.info("Triggering on-demand digest for topic '%s'", topic["name"])
            if job.id.startswith("watch_"):
                await self._run_watch_topic(
                    topic, progress=progress, override_channel=override_channel
                )
            else:
                await self._run_topic(topic, progress=progress, override_channel=override_channel)

        # Pass 1: exact tag match
        for job in jobs:
            tags = [t.lower() for t in job.args[0].get("tags", [])]
            if query in tags:
                await _dispatch(job)
                return True

        # Pass 2: partial name match
        for job in jobs:
            name = job.args[0]["name"].lower()
            if query in name or name in query:
                await _dispatch(job)
                return True

        logger.warning("No topic matching query '%s'", topic_query)
        return False

    async def run_all_now(self, override_channel=None) -> None:
        """Trigger all digest and watch-mode topics immediately."""
        for job in self._scheduler.get_jobs():
            if job.id.startswith("digest_"):
                logger.info("Triggering on-demand digest for topic '%s'", job.args[0]["name"])
                await self._run_topic(job.args[0], override_channel=override_channel)
            elif job.id.startswith("watch_"):
                logger.info("Triggering on-demand poll for watch topic '%s'", job.args[0]["name"])
                await self._run_watch_topic(job.args[0], override_channel=override_channel)

    def find_watch_topic(self, topic_query: str) -> dict | None:
        """Return the watch-mode topic dict matching *topic_query* by tag or name, or None."""
        query = topic_query.strip().lower()
        jobs = [j for j in self._scheduler.get_jobs() if j.id.startswith(("watch_", "digest_"))]

        for job in jobs:
            tags = [t.lower() for t in job.args[0].get("tags", [])]
            if query in tags:
                return job.args[0]
        for job in jobs:
            name = job.args[0]["name"].lower()
            if query in name or name in query:
                return job.args[0]
        return None

    def get_watch_topic_names(self) -> list[str]:
        """Return names of all watch-mode topics."""
        return [
            job.args[0]["name"]
            for job in self._scheduler.get_jobs()
            if job.id.startswith(("watch_", "digest_"))
        ]

    @property
    def watch_keywords(self) -> WatchKeywords:
        return self._watch_keywords

    def start(self):
        self._scheduler.start()
        logger.info("Digest scheduler started (%d topics)", len(self._topics))

    def shutdown(self):
        self._scheduler.shutdown(wait=False)
