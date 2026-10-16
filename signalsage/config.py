"""Configuration loading with environment variable substitution."""

import logging
import os
import re
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised when configuration is syntactically valid but unsafe or incomplete."""


def _positive_number(value: Any, path: str, *, allow_zero: bool = False) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{path} must be a number")
    if value < 0 or (value == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ConfigError(f"{path} must be {qualifier}")


def validate_config(config: dict) -> dict:
    """Validate application settings and return them unchanged."""
    if not isinstance(config, dict):
        raise ConfigError("configuration root must be a mapping")
    platforms = config.get("platforms", {}) or {}
    if not isinstance(platforms, dict):
        raise ConfigError("platforms must be a mapping")
    enabled = 0
    for name in ("slack", "discord"):
        platform = platforms.get(name, {}) or {}
        if not isinstance(platform, dict):
            raise ConfigError(f"platforms.{name} must be a mapping")
        if platform.get("enabled"):
            enabled += 1
            if not platform.get("bot_token"):
                raise ConfigError(f"platforms.{name}.bot_token is required when enabled")
            if name == "slack" and not platform.get("app_token"):
                raise ConfigError("platforms.slack.app_token is required when enabled")
    if platforms and not enabled:
        raise ConfigError("at least one platform must be enabled")

    intel = config.get("intel", {}) or {}
    for key in ("timeout", "cache_ttl", "max_iocs_per_message"):
        if key in intel:
            _positive_number(intel[key], f"intel.{key}")

    digest = config.get("digest", {}) or {}
    if digest:
        provider = str(digest.get("llm_provider", "ollama")).lower()
        if provider not in {"ollama", "anthropic", "cli"}:
            raise ConfigError("digest.llm_provider must be ollama, anthropic, or cli")
        if provider == "anthropic" and not digest.get("anthropic_api_key"):
            raise ConfigError("digest.anthropic_api_key is required for the anthropic backend")
        timezone = str(digest.get("timezone", "UTC"))
        try:
            ZoneInfo(timezone)
        except Exception as exc:
            raise ConfigError(f"digest.timezone is invalid: {timezone}") from exc
        schedule = digest.get("default_schedule")
        if schedule:
            try:
                CronTrigger.from_crontab(str(schedule), timezone=timezone)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"digest.default_schedule is invalid: {schedule}") from exc
        for key in (
            "collection_minutes",
            "retention_days",
            "article_chars",
            "max_prompt_chars",
            "top_stories_count",
        ):
            if key in digest:
                _positive_number(digest[key], f"digest.{key}")
    return config


def validate_digests(watchlist: dict, timezone: str = "UTC") -> dict:
    """Validate topic definitions, including source URLs and cron expressions."""
    topics = watchlist.get("topics", [])
    if not isinstance(topics, list):
        raise ConfigError("digest topics must be a list")
    names: set[str] = set()
    for index, topic in enumerate(topics):
        path = f"topics[{index}]"
        if not isinstance(topic, dict):
            raise ConfigError(f"{path} must be a mapping")
        name = str(topic.get("name", "")).strip()
        if not name:
            raise ConfigError(f"{path}.name is required")
        if name.casefold() in names:
            raise ConfigError(f"duplicate digest topic name: {name}")
        names.add(name.casefold())
        sources = topic.get("sources", [])
        if not isinstance(sources, list):
            raise ConfigError(f"{path}.sources must be a list")
        for source_index, source in enumerate(sources):
            url = source.get("url", "") if isinstance(source, dict) else ""
            if not str(url).startswith(("http://", "https://")):
                raise ConfigError(f"{path}.sources[{source_index}].url must be HTTP(S)")
        schedule = topic.get("schedule")
        if schedule and not topic.get("watch_mode"):
            try:
                CronTrigger.from_crontab(str(schedule), timezone=timezone)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"{path}.schedule is invalid: {schedule}") from exc
    return watchlist


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


def _deep_merge(base: Any, override: Any) -> Any:
    """Merge *override* into *base*: mappings merge key by key, anything else replaces."""
    if isinstance(base, dict) and isinstance(override, dict):
        merged = dict(base)
        for key, value in override.items():
            merged[key] = _deep_merge(base.get(key), value) if key in base else value
        return merged
    return override


def load_config(path: str = "config/config.yaml") -> dict:
    """Load and expand the main configuration file.

    A sibling ``*.local.yaml`` (e.g. ``config/config.local.yaml``) is gitignored
    and merged over it, so an install keeps private settings such as its
    interest profile without editing the tracked file that ``git pull`` updates.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        local = Path(path).with_suffix(".local.yaml")
        if local.is_file():
            with open(local, encoding="utf-8") as fh:
                raw = _deep_merge(raw, yaml.safe_load(fh) or {})
            logger.info("Merged local config overrides from %s", local)
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
