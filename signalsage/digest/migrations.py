"""Versioned, transactional SQLite schema migrations."""

import sqlite3

SCHEMA_VERSION = 1

MIGRATIONS: dict[int, str] = {
    1: """
        CREATE TABLE IF NOT EXISTS articles (
            id TEXT PRIMARY KEY, identity TEXT NOT NULL, version TEXT NOT NULL,
            data TEXT NOT NULL, collected REAL NOT NULL, body TEXT, body_kind TEXT,
            enrichment TEXT, cached_summary TEXT, summary_key TEXT);
        CREATE INDEX IF NOT EXISTS article_identity ON articles(identity, collected);
        CREATE TABLE IF NOT EXISTS topic_articles (
            topic TEXT NOT NULL, article TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'discovered',
            profile TEXT, reason TEXT, score REAL, PRIMARY KEY(topic, article));
        CREATE TABLE IF NOT EXISTS ignored_versions (
            topic TEXT NOT NULL, article TEXT NOT NULL, PRIMARY KEY(topic, article));
        CREATE TABLE IF NOT EXISTS sources (
            topic TEXT NOT NULL, url TEXT NOT NULL, last_success REAL, last_attempt REAL,
            status TEXT, error TEXT, PRIMARY KEY(topic, url));
        CREATE TABLE IF NOT EXISTS outbox (
            id TEXT PRIMARY KEY, destination TEXT NOT NULL, topic TEXT NOT NULL,
            body TEXT NOT NULL, offset INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt REAL NOT NULL DEFAULT 0, error TEXT, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS deliveries (
            destination TEXT NOT NULL, article TEXT NOT NULL, outbox TEXT NOT NULL,
            PRIMARY KEY(destination, article));
        CREATE TABLE IF NOT EXISTS message_articles (
            platform TEXT NOT NULL, message TEXT NOT NULL, article TEXT NOT NULL,
            PRIMARY KEY(platform, message));
        CREATE TABLE IF NOT EXISTS message_stories (
            platform TEXT NOT NULL, message TEXT NOT NULL, position INTEGER NOT NULL,
            article TEXT NOT NULL, PRIMARY KEY(platform, message, position));
        CREATE TABLE IF NOT EXISTS feedback (
            article TEXT NOT NULL, actor TEXT NOT NULL, useful INTEGER NOT NULL,
            PRIMARY KEY(article, actor));
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY, topic TEXT, started REAL, metrics TEXT);
    """,
}


def migrate(db: sqlite3.Connection) -> None:
    """Upgrade *db* to the current schema or reject a newer database."""
    db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = db.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    current = int(row[0]) if row else 0
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema {current} is newer than supported schema {SCHEMA_VERSION}"
        )
    for version in range(current + 1, SCHEMA_VERSION + 1):
        db.executescript(MIGRATIONS[version])
        if row is None and version == 1:
            db.execute("INSERT INTO schema_version(version) VALUES(?)", (version,))
        else:
            db.execute("UPDATE schema_version SET version=?", (version,))
