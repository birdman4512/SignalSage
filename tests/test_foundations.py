"""Tests for startup validation, migrations, and operational helpers."""

import asyncio
import json
import logging
import sqlite3

import pytest

from signalsage.config import ConfigError, validate_config, validate_digests
from signalsage.digest.migrations import SCHEMA_VERSION, migrate
from signalsage.observability import JsonFormatter, supervise


def test_config_validation_rejects_missing_enabled_platform_secret():
    with pytest.raises(ConfigError, match="bot_token"):
        validate_config({"platforms": {"slack": {"enabled": True}}})


def test_digest_validation_rejects_duplicate_names():
    with pytest.raises(ConfigError, match="duplicate"):
        validate_digests({"topics": [{"name": "News"}, {"name": "news"}]})


def test_migration_versions_new_database(tmp_path):
    db = sqlite3.connect(tmp_path / "articles.sqlite3")
    with db:
        migrate(db)
    assert db.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
    assert db.execute("SELECT name FROM sqlite_master WHERE name='outbox'").fetchone()
    db.close()


def test_migration_rejects_newer_database(tmp_path):
    db = sqlite3.connect(tmp_path / "articles.sqlite3")
    db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    db.execute("INSERT INTO schema_version VALUES(?)", (SCHEMA_VERSION + 1,))
    with pytest.raises(RuntimeError, match="newer"):
        migrate(db)
    db.close()


def test_json_formatter_is_machine_readable():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["event"] == "hello world"
    assert payload["level"] == "INFO"


async def test_supervisor_restarts_failed_component():
    attempts = 0

    async def component():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await supervise("test", component, max_backoff=0)
    assert attempts == 2
