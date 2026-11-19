"""Runtime-editable include/exclude keywords per digest topic (watch_keywords.json)."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_json(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load %s: %s", path, exc)
    return {}


def _save_json(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not save %s: %s", path, exc)


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
