"""Persistent digest history for trend detection and source health monitoring."""

import hashlib
import json
import logging
from datetime import date, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

_KEEP_DAYS = 30  # prune entries older than this


def _headline_hash(headline: str) -> str:
    """Stable 12-char hash of a normalised headline for deduplication."""
    normalised = headline.lower().strip()
    return hashlib.md5(normalised.encode()).hexdigest()[:12]


_LLM_TIMING_SAMPLES = 50  # rolling window size


class DigestHistory:
    """
    Persists three data stores under *data_dir*:

    digest_history.json
        {topic: {date_iso: [{"hash": str, "headline": str}, ...]}}
        Used for trend detection — classifying items as "new" or "trending".

    source_health.json
        {source_name: {date_iso: bool}}   True = returned content, False = empty/failed
        Used for consecutive-failure alerting.

    llm_timing.json
        {"samples": [{"chars": int, "seconds": float}, ...]}
        Rolling window of LLM call durations used to estimate future ETAs.
    """

    def __init__(self, data_dir: str = "data") -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._history_path = self._dir / "digest_history.json"
        self._health_path = self._dir / "source_health.json"
        self._timing_path = self._dir / "llm_timing.json"
        self._history: dict = self._load(self._history_path)
        self._health: dict = self._load(self._health_path)
        self._timing: dict = self._load(self._timing_path) or {"samples": []}

    # ── I/O helpers ─────────────────────────────────────────────────────────

    def _load(self, path: Path) -> dict:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not load %s: %s", path, exc)
        return {}

    def _save(self, path: Path, data: dict) -> None:
        try:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not save %s: %s", path, exc)

    def _prune(self) -> None:
        """Drop entries older than _KEEP_DAYS to keep files small."""
        cutoff = (date.today() - timedelta(days=_KEEP_DAYS)).isoformat()
        for topic in list(self._history):
            self._history[topic] = {d: v for d, v in self._history[topic].items() if d >= cutoff}
        for source in list(self._health):
            self._health[source] = {d: v for d, v in self._health[source].items() if d >= cutoff}

    # ── Digest item history ──────────────────────────────────────────────────

    def record_items(self, topic: str, items: list[dict]) -> None:
        """Persist today's digest items for *topic*."""
        today = date.today().isoformat()
        records = [
            {"hash": _headline_hash(i.get("headline", "")), "headline": i.get("headline", "")}
            for i in items
            if i.get("headline", "").strip()
        ]
        self._history.setdefault(topic, {})[today] = records
        self._prune()
        self._save(self._history_path, self._history)

    def classify_items(self, topic: str, items: list[dict]) -> dict[str, str]:
        """
        Return {headline_hash: "trending" | "new"} for each item in *items*.

        "trending" means the headline appeared in this topic's history within
        the last 7 days (but not today — today's run isn't recorded yet).
        """
        today = date.today().isoformat()
        cutoff = (date.today() - timedelta(days=7)).isoformat()
        past_hashes: set[str] = set()
        for day, records in self._history.get(topic, {}).items():
            if cutoff <= day < today:
                for r in records:
                    past_hashes.add(r.get("hash", ""))

        return {
            _headline_hash(i.get("headline", "")): (
                "trending" if _headline_hash(i.get("headline", "")) in past_hashes else "new"
            )
            for i in items
        }

    # ── Source health ────────────────────────────────────────────────────────

    def record_source_results(self, results: dict[str, bool]) -> None:
        """Record today's fetch result per source. True = returned content."""
        today = date.today().isoformat()
        for source, ok in results.items():
            self._health.setdefault(source, {})[today] = ok
        self._prune()
        self._save(self._health_path, self._health)

    def get_chronically_failing_sources(self, consecutive_days: int = 3) -> list[str]:
        """Return sources that have returned no content for *consecutive_days* days in a row."""
        today = date.today()
        failing: list[str] = []
        for source, days in self._health.items():
            streak = 0
            for i in range(consecutive_days):
                day = (today - timedelta(days=i)).isoformat()
                if days.get(day) is False:
                    streak += 1
                else:
                    break
            if streak >= consecutive_days:
                failing.append(source)
        return failing

    # ── LLM timing ───────────────────────────────────────────────────────────

    def record_llm_timing(self, chars: int, seconds: float) -> None:
        """Record one LLM call duration. Keeps the last _LLM_TIMING_SAMPLES samples."""
        samples: list = self._timing.setdefault("samples", [])
        samples.append({"chars": chars, "seconds": seconds})
        if len(samples) > _LLM_TIMING_SAMPLES:
            self._timing["samples"] = samples[-_LLM_TIMING_SAMPLES:]
        self._save(self._timing_path, self._timing)

    def estimate_llm_seconds(self, chars: int) -> float | None:
        """
        Return an estimated LLM processing time in seconds for *chars* input characters,
        based on the historical chars-per-second rate from recorded samples.
        Returns None if fewer than 3 samples are available.
        """
        samples: list = self._timing.get("samples", [])
        if len(samples) < 3:
            return None
        total_chars = sum(s["chars"] for s in samples)
        total_seconds = sum(s["seconds"] for s in samples)
        if total_seconds == 0:
            return None
        chars_per_second = total_chars / total_seconds
        return chars / chars_per_second
