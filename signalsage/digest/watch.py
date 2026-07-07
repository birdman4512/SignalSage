"""Runtime state for watch-mode digest topics: keyword filters and seen-item tracking."""

import hashlib
import logging
from datetime import date, timedelta
from pathlib import Path

from signalsage.digest.history import _load_json, _save_json

logger = logging.getLogger(__name__)

_KEEP_DAYS = 30  # prune seen-item entries older than this


def item_id(item: dict) -> str:
    """Return a stable identity for a watch-mode item.

    A feed entry's link is stable across polls, so it is checked exactly once
    ever. Items with no link (whole-page HTML fetches) fall back to a hash of
    their title+summary, so a changed page is treated as new content.
    """
    link = str(item.get("link") or "").strip()
    if link:
        return link
    raw = f"{item.get('title', '')}\n{item.get('summary', '')}"
    return "h:" + hashlib.md5(raw.encode()).hexdigest()[:16]


def matches_keywords(item: dict, include: list[str], exclude: list[str]) -> bool:
    """Plain case-insensitive substring match against title+summary.

    Empty *include* means "match everything". Any *exclude* hit vetoes a match.
    """
    haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    if any(word.lower() in haystack for word in exclude if word.strip()):
        return False
    if not include:
        return True
    return any(word.lower() in haystack for word in include if word.strip())


class WatchKeywords:
    """Persists per-topic include/exclude keyword lists for watch-mode topics.

    keywords.json: {topic: {"include": [...], "exclude": [...]}}
    """

    def __init__(self, data_dir: str = "data") -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "watch_keywords.json"
        self._data: dict = _load_json(self._path)

    def seed_defaults(self, topic: str, include: list[str], exclude: list[str]) -> None:
        """Seed *topic*'s keyword lists from YAML config, only if it has no runtime state yet."""
        if topic in self._data:
            return
        if not include and not exclude:
            return
        self._data[topic] = {"include": list(include), "exclude": list(exclude)}
        _save_json(self._path, self._data)

    def get(self, topic: str) -> tuple[list[str], list[str]]:
        entry = self._data.get(topic, {})
        return list(entry.get("include", [])), list(entry.get("exclude", []))

    def add(self, topic: str, word: str, exclude: bool = False) -> bool:
        """Add *word* to the include (or exclude) list. Returns False if already present."""
        key = "exclude" if exclude else "include"
        entry = self._data.setdefault(topic, {"include": [], "exclude": []})
        entry.setdefault(key, [])
        word = word.strip()
        if not word or word.lower() in (w.lower() for w in entry[key]):
            return False
        entry[key].append(word)
        _save_json(self._path, self._data)
        return True

    def remove(self, topic: str, word: str, exclude: bool = False) -> bool:
        """Remove *word* from the include (or exclude) list. Returns False if not present."""
        key = "exclude" if exclude else "include"
        entry = self._data.get(topic, {})
        words = entry.get(key, [])
        lowered = word.strip().lower()
        matching = [w for w in words if w.lower() == lowered]
        if not matching:
            return False
        entry[key] = [w for w in words if w.lower() != lowered]
        _save_json(self._path, self._data)
        return True


class WatchSeenItems:
    """Tracks which watch-mode items have already been evaluated, per topic.

    watch_seen.json: {topic: {item_id: date_iso}}
    """

    def __init__(self, data_dir: str = "data") -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "watch_seen.json"
        self._data: dict = _load_json(self._path)
        self._last_prune_day: str = ""

    def _prune_if_due(self) -> None:
        today = date.today().isoformat()
        if self._last_prune_day == today:
            return
        cutoff = (date.today() - timedelta(days=_KEEP_DAYS)).isoformat()
        for topic in list(self._data):
            self._data[topic] = {k: v for k, v in self._data[topic].items() if v >= cutoff}
        self._last_prune_day = today

    def filter_new(self, topic: str, items: list[dict]) -> list[dict]:
        """Return only the items in *items* that haven't been seen before for *topic*."""
        seen = self._data.get(topic, {})
        return [i for i in items if item_id(i) not in seen]

    def mark_seen(self, topic: str, items: list[dict]) -> None:
        """Record every item in *items* as seen for *topic*, regardless of match outcome."""
        if not items:
            return
        today = date.today().isoformat()
        entry = self._data.setdefault(topic, {})
        for i in items:
            entry[item_id(i)] = today
        self._prune_if_due()
        _save_json(self._path, self._data)
