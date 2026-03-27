"""Configuration loading with environment variable substitution."""

import os
import re
import logging
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _expand_env(value: Any) -> Any:
    """Recursively walk dict/list/str and substitute ${VAR} patterns."""
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, str):
        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            env_value = os.environ.get(var_name, "")
            if not env_value:
                logger.debug("Environment variable %s not set", var_name)
            return env_value
        return _ENV_VAR_RE.sub(replacer, value)
    return value


def load_config(path: str = "config/config.yaml") -> dict:
    """Load and expand the main configuration file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return _expand_env(raw) or {}
    except FileNotFoundError:
        logger.error("Config file not found: %s", path)
        raise
    except yaml.YAMLError as exc:
        logger.error("Failed to parse config YAML: %s", exc)
        raise


def load_watchlist(path: str = "config/watchlist.yaml") -> dict:
    """Load and expand the watchlist configuration file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return _expand_env(raw) or {}
    except FileNotFoundError:
        logger.error("Watchlist file not found: %s", path)
        raise
    except yaml.YAMLError as exc:
        logger.error("Failed to parse watchlist YAML: %s", exc)
        raise
