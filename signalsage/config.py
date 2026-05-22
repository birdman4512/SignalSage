"""Configuration loading with environment variable substitution."""

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Supports ${VAR} and ${VAR:-default} syntax
_ENV_VAR_RE = re.compile(r"\$\{([^}:-]+)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    """Recursively walk dict/list/str and substitute ${VAR} and ${VAR:-default} patterns."""
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, str):

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            has_default = match.group(2) is not None
            default = match.group(2) if has_default else ""
            env_value = os.environ.get(var_name)
            if env_value is not None:
                return env_value
            if has_default:
                return default
            logger.debug("Environment variable %s not set (no default)", var_name)
            return ""

        result = _ENV_VAR_RE.sub(replacer, value)
        if result.lower() == "true":
            return True
        if result.lower() == "false":
            return False
        return result
    return value


def load_config(path: str = "config/config.yaml") -> dict:
    """Load and expand the main configuration file."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return _expand_env(raw) or {}
    except FileNotFoundError:
        logger.error("Config file not found: %s", path)
        raise
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config YAML: %s", exc)
        raise


def load_digests(path: str = "config/digests") -> dict:
    """Load every digest topic from the digests directory.

    Each ``*.yaml`` file in the directory defines one digest topic — its keys
    are the topic fields (``name``, ``schedule``, ``sources``, ...). Dropping a
    new file into the directory adds a new digest; no other file needs editing.

    Files using a ``*.local.yaml`` suffix are install-private and gitignored, so
    a deployment can carry private digests alongside the repo's core set. A file
    may also wrap a ``topics:`` list to define several topics at once.

    Returns ``{"topics": [...]}`` so callers see the same shape as before.
    A missing directory is non-fatal — it just yields no topics.
    """
    dir_path = Path(path)
    if not dir_path.is_dir():
        logger.warning("Digest directory not found: %s — no digest topics loaded", path)
        return {"topics": []}

    topics: list[dict] = []
    for file in sorted(dir_path.glob("*.yaml")):
        try:
            with open(file, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            logger.error("Failed to parse digest file %s: %s", file.name, exc)
            raise

        if raw is None:
            logger.warning("Digest file %s is empty — skipping", file.name)
            continue

        raw = _expand_env(raw)
        if isinstance(raw, list):
            topics.extend(raw)
        elif isinstance(raw, dict) and "topics" in raw:
            topics.extend(raw.get("topics") or [])
        elif isinstance(raw, dict):
            topics.append(raw)
        else:
            logger.warning("Ignoring digest file %s — unexpected top-level type", file.name)

    logger.info("Loaded %d digest topic(s) from %s", len(topics), path)
    return {"topics": topics}
