"""Durable article state and an at-least-once delivery outbox, using SQLite."""

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .ranking import article_identity, canonical_url, fingerprint, similar_story


class ArticleStore:
    def __init__(self, data_dir: str):
        self.path = Path(data_dir) / "articles.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS articles (
                    id TEXT PRIMARY KEY, identity TEXT NOT NULL, version TEXT NOT NULL,
                    data TEXT NOT NULL, collected REAL NOT NULL,
                    body TEXT, body_kind TEXT, enrichment TEXT,
                    cached_summary TEXT, summary_key TEXT
                );
                CREATE INDEX IF NOT EXISTS article_identity ON articles(identity, collected);
                CREATE TABLE IF NOT EXISTS topic_articles (
                    topic TEXT NOT NULL, article TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'discovered',
                    profile TEXT, reason TEXT, score REAL, PRIMARY KEY(topic, article)
                );
                CREATE TABLE IF NOT EXISTS ignored_versions (
                    topic TEXT NOT NULL, article TEXT NOT NULL, PRIMARY KEY(topic, article)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    topic TEXT NOT NULL, url TEXT NOT NULL, last_success REAL,
                    last_attempt REAL, status TEXT, error TEXT, PRIMARY KEY(topic, url)
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    id TEXT PRIMARY KEY, destination TEXT NOT NULL, topic TEXT NOT NULL,
                    body TEXT NOT NULL, offset INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0, error TEXT,
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    destination TEXT NOT NULL, article TEXT NOT NULL, outbox TEXT NOT NULL,
                    PRIMARY KEY(destination, article)
                );
                CREATE TABLE IF NOT EXISTS message_articles (
                    platform TEXT NOT NULL, message TEXT NOT NULL, article TEXT NOT NULL,
                    PRIMARY KEY(platform, message)
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    article TEXT NOT NULL, actor TEXT NOT NULL, useful INTEGER NOT NULL,
                    PRIMARY KEY(article, actor)
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY, topic TEXT, started REAL, metrics TEXT
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        # WAL + NORMAL: a commit no longer fsyncs. Measured on the production
        # disk, FULL cost 65 ms per commit versus 0.5 ms — enough that a publish
        # run's per-article decisions blocked the event loop for ~10s and
        # dropped the Slack socket. A power cut can lose the last few commits
        # but can't corrupt the database; delivery is at-least-once regardless.
        db.execute("PRAGMA synchronous=NORMAL")
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def checkpoint(self, topic: str, url: str) -> float | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT last_success FROM sources WHERE topic=? AND url=?", (topic, url)
            ).fetchone()
            return row[0] if row else None

    def ingest(
        self,
        topic: str,
        source: dict,
        items: list[dict],
        error: str | None = None,
        bootstrap_cutoff: float | None = None,
    ) -> int:
        """Persist items and their collection checkpoint in the SAME transaction."""
        now = time.time()
        added = 0
        with self.connect() as db:
            db.execute(
                """INSERT INTO sources(topic,url,last_attempt,status,error) VALUES(?,?,?,?,?)
                ON CONFLICT(topic,url) DO UPDATE SET last_attempt=excluded.last_attempt,
                status=excluded.status,error=excluded.error""",
                (
                    topic,
                    source["url"],
                    now,
                    "error" if error else "ok" if items else "empty",
                    error,
                ),
            )
            if error:
                return 0
            for item in items:
                record = dict(
                    item,
                    source_name=source.get("name", ""),
                    source_url=source["url"],
                    source_image_url=source.get("image_url"),
                )
                identity, version = article_identity(record)
                article = fingerprint([identity, version])
                if db.execute(
                    "SELECT 1 FROM ignored_versions WHERE topic=? AND article=?", (topic, article)
                ).fetchone():
                    continue
                published = record.get("published_ts")
                if (
                    bootstrap_cutoff is not None
                    and published is not None
                    and published < bootstrap_cutoff
                ):
                    db.execute(
                        "INSERT OR IGNORE INTO ignored_versions VALUES(?,?)", (topic, article)
                    )
                    continue
                record.update(
                    id=article,
                    identity=identity,
                    version=version,
                    link=canonical_url(record.get("link", "")),
                )
                db.execute(
                    "INSERT OR IGNORE INTO articles(id,identity,version,data,collected) VALUES(?,?,?,?,?)",
                    (article, identity, version, json.dumps(record), now),
                )
                cur = db.execute(
                    "INSERT OR IGNORE INTO topic_articles(topic,article) VALUES(?,?)",
                    (topic, article),
                )
                added += cur.rowcount
            db.execute(
                "UPDATE sources SET last_success=? WHERE topic=? AND url=?",
                (now, topic, source["url"]),
            )
        return added

    def candidates(self, topic: str, profile: str, max_age_days: float | None = None) -> list[dict]:
        """Undelivered, unrejected latest versions for *topic*.

        *max_age_days* drops stale backlog: an article first collected, or
        published, longer ago than this is old news and is never posted, even
        on a quiet day with nothing newer to crowd it out. It also keeps each
        publish run's dedup scan proportional to recent volume rather than to
        the whole retention window.
        """
        cutoff = time.time() - max_age_days * 86400 if max_age_days else 0.0
        with self.connect() as db:
            rows = db.execute(
                """SELECT a.* FROM articles a JOIN topic_articles t ON t.article=a.id
                WHERE t.topic=? AND a.collected>=?
                AND (t.state!='rejected' OR t.profile!=? OR t.profile IS NULL)
                AND NOT EXISTS (SELECT 1 FROM articles newer
                    WHERE newer.identity=a.identity AND newer.collected>a.collected)
                ORDER BY a.collected DESC""",
                (topic, cutoff, profile),
            ).fetchall()
        articles = [self._article(row) for row in rows]
        return [a for a in articles if (a.get("published_ts") or cutoff) >= cutoff]

    @staticmethod
    def _article(row) -> dict:
        data = json.loads(row["data"])
        data.update(
            body=row["body"],
            body_kind=row["body_kind"],
            enrichment=json.loads(row["enrichment"] or "[]"),
            cached_summary=row["cached_summary"],
            summary_key=row["summary_key"],
        )
        return data

    def decision(
        self, topic: str, article: str, profile: str, state: str, score: float, reasons: list[str]
    ):
        with self.connect() as db:
            db.execute(
                "UPDATE topic_articles SET state=?,profile=?,score=?,reason=? WHERE topic=? AND article=?",
                (state, profile, score, json.dumps(reasons), topic, article),
            )

    def cache_content(self, article: str, body: str, kind: str, enrichment: list[dict]):
        with self.connect() as db:
            db.execute(
                "UPDATE articles SET body=?,body_kind=?,enrichment=? WHERE id=?",
                (body, kind, json.dumps(enrichment), article),
            )

    def cache_summary(self, article: str, key: str, summary: str):
        with self.connect() as db:
            db.execute(
                "UPDATE articles SET cached_summary=?,summary_key=? WHERE id=?",
                (summary, key, article),
            )
            db.execute(
                "UPDATE topic_articles SET state='summarized' WHERE article=? AND state!='rejected'",
                (article,),
            )

    def reservations(self, destination: str) -> tuple[set[str], list[dict]]:
        """Snapshot of what *destination* already has: (article IDs, recent articles).

        Pending deliveries count too, preventing simultaneous topic duplicates.
        Take one snapshot per publish run and test candidates with ``reserved``
        rather than calling ``is_reserved`` per candidate, which re-reads and
        re-decodes every recent delivery each time.
        """
        with self.connect() as db:
            ids = {
                row[0]
                for row in db.execute(
                    "SELECT article FROM deliveries WHERE destination=?", (destination,)
                )
            }
            recent = [
                json.loads(row[0])
                for row in db.execute(
                    """SELECT a.data FROM deliveries d JOIN articles a ON a.id=d.article
                    WHERE d.destination=? AND a.collected>?""",
                    (destination, time.time() - 7 * 86400),
                )
            ]
        return ids, recent

    @staticmethod
    def reserved(reservations: tuple[set[str], list[dict]], item: dict) -> bool:
        ids, recent = reservations
        return item["id"] in ids or any(similar_story(item, other) for other in recent)

    def is_reserved(self, destination: str, item: dict) -> bool:
        return self.reserved(self.reservations(destination), item)

    def enqueue(self, destination: str, topic: str, body: dict, articles: list[dict]) -> str:
        outbox_id = str(uuid.uuid4())
        with self.connect() as db:
            db.execute(
                "INSERT INTO outbox(id,destination,topic,body,created) VALUES(?,?,?,?,?)",
                (outbox_id, destination, topic, json.dumps(body), time.time()),
            )
            for item in articles:
                db.execute(
                    "INSERT INTO deliveries(destination,article,outbox) VALUES(?,?,?)",
                    (destination, item["id"], outbox_id),
                )
                db.execute(
                    "UPDATE topic_articles SET state='pending' WHERE topic=? AND article=?",
                    (topic, item["id"]),
                )
        return outbox_id

    def pending(self, force: bool = False) -> list[dict]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM outbox o WHERE state='pending' AND next_attempt<=?
                    AND NOT EXISTS (SELECT 1 FROM outbox blocked WHERE blocked.destination=o.destination
                        AND blocked.state='pending' AND blocked.next_attempt>?) ORDER BY created""",
                    (
                        float("inf") if force else time.time(),
                        float("inf") if force else time.time(),
                    ),
                )
            ]

    def acknowledge(self, outbox_id: str, offset: int):
        with self.connect() as db:
            db.execute("UPDATE outbox SET offset=MAX(offset,?) WHERE id=?", (offset, outbox_id))

    def delivered(self, outbox_id: str):
        with self.connect() as db:
            db.execute("UPDATE outbox SET state='delivered',error=NULL WHERE id=?", (outbox_id,))
            db.execute(
                """UPDATE topic_articles SET state='delivered' WHERE article IN
                (SELECT article FROM deliveries WHERE outbox=?) AND NOT EXISTS
                (SELECT 1 FROM deliveries d JOIN outbox o ON o.id=d.outbox
                 WHERE d.article=topic_articles.article AND o.state='pending')""",
                (outbox_id,),
            )

    def failed(self, outbox_id: str, error: Exception):
        with self.connect() as db:
            attempts = (
                db.execute("SELECT attempts FROM outbox WHERE id=?", (outbox_id,)).fetchone()[0] + 1
            )
            retry_after = 0.0
            response = getattr(error, "response", None)
            if response is not None:
                try:
                    retry_after = float(response.headers.get("Retry-After", 0))
                except (TypeError, ValueError, AttributeError):
                    pass
            delay = max(retry_after, min(3600, 30 * 2 ** min(attempts, 7)))
            db.execute(
                "UPDATE outbox SET attempts=?,next_attempt=?,error=? WHERE id=?",
                (
                    attempts,
                    time.time() + delay,
                    f"{type(error).__name__}: {error}"[:500],
                    outbox_id,
                ),
            )

    def record_feedback(self, article_prefix: str, actor: str, useful: bool) -> bool:
        with self.connect() as db:
            rows = db.execute(
                "SELECT id FROM articles WHERE id LIKE ?", (article_prefix + "%",)
            ).fetchall()
            if len(rows) != 1:
                return False
            db.execute(
                "INSERT OR REPLACE INTO feedback(article,actor,useful) VALUES(?,?,?)",
                (rows[0][0], actor, int(useful)),
            )
        return True

    def record_message(self, platform: str, message: str, article: str) -> None:
        """Remember which article a posted story message carries, for reaction feedback."""
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO message_articles(platform,message,article) VALUES(?,?,?)",
                (platform, message, article),
            )

    def react_feedback(
        self, platform: str, message: str, actor: str, useful: bool, removed: bool = False
    ) -> bool:
        """Apply a thumbs reaction on a story message as feedback.

        Adding a reaction sets the actor's vote (last one wins); removing it
        clears the vote only if it is still the one that reaction set.
        """
        with self.connect() as db:
            row = db.execute(
                "SELECT article FROM message_articles WHERE platform=? AND message=?",
                (platform, message),
            ).fetchone()
            if (
                row is None
                or not db.execute("SELECT 1 FROM articles WHERE id=?", (row[0],)).fetchone()
            ):
                return False
            if removed:
                db.execute(
                    "DELETE FROM feedback WHERE article=? AND actor=? AND useful=?",
                    (row[0], actor, int(useful)),
                )
            else:
                db.execute(
                    "INSERT OR REPLACE INTO feedback(article,actor,useful) VALUES(?,?,?)",
                    (row[0], actor, int(useful)),
                )
        return True

    def feedback_weights(self) -> dict[str, float]:
        from urllib.parse import urlsplit

        weights: dict[str, float] = {}
        with self.connect() as db:
            rows = db.execute(
                "SELECT a.data,f.useful FROM feedback f JOIN articles a ON a.id=f.article"
            ).fetchall()
        for row in rows:
            host = urlsplit(json.loads(row[0]).get("link", "")).hostname or ""
            weights[host] = weights.get(host, 0) + (0.25 if row[1] else -0.25)
        return weights

    def record_run(self, topic: str, started: float, metrics: dict):
        with self.connect() as db:
            db.execute(
                "INSERT INTO runs(topic,started,metrics) VALUES(?,?,?)",
                (topic, started, json.dumps(metrics)),
            )

    def prune(self, retention_days: int = 90):
        """Bound completed history; never discard undelivered work or feedback."""
        cutoff = time.time() - max(7, retention_days) * 86400
        # Superseded versions (a newer version of the same URL exists) are never
        # candidates again, and whole-page sources that change on every fetch
        # (e.g. live solar/propagation pages) create one every collection — so
        # they get a short retention instead of waiting out the full window.
        superseded_cutoff = time.time() - 2 * 86400
        with self.connect() as db:
            removable = [
                r[0]
                for r in db.execute(
                    """SELECT a.id FROM articles a WHERE
                (
                    (a.collected<? AND NOT EXISTS (SELECT 1 FROM topic_articles t
                        WHERE t.article=a.id AND t.state NOT IN ('delivered','rejected')))
                    OR (a.collected<? AND EXISTS (SELECT 1 FROM articles newer
                        WHERE newer.identity=a.identity AND newer.collected>a.collected))
                )
                AND NOT EXISTS (SELECT 1 FROM feedback f WHERE f.article=a.id)
                AND NOT EXISTS (SELECT 1 FROM deliveries d JOIN outbox o ON o.id=d.outbox WHERE d.article=a.id AND o.state='pending')""",
                    (cutoff, superseded_cutoff),
                )
            ]
            for article in removable:
                db.execute(
                    "INSERT OR IGNORE INTO ignored_versions SELECT topic,article FROM topic_articles WHERE article=?",
                    (article,),
                )
                db.execute("DELETE FROM deliveries WHERE article=?", (article,))
                db.execute("DELETE FROM message_articles WHERE article=?", (article,))
                db.execute("DELETE FROM topic_articles WHERE article=?", (article,))
                db.execute("DELETE FROM articles WHERE id=?", (article,))
            db.execute(
                "DELETE FROM outbox WHERE state='delivered' AND created<? AND NOT EXISTS (SELECT 1 FROM deliveries WHERE outbox=outbox.id)",
                (cutoff,),
            )
            db.execute("DELETE FROM runs WHERE started<?", (cutoff,))

    def status(self) -> dict:
        with self.connect() as db:
            return {
                "articles": db.execute("SELECT COUNT(*) FROM articles").fetchone()[0],
                "pending_deliveries": db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE state='pending'"
                ).fetchone()[0],
                "source_errors": db.execute(
                    "SELECT COUNT(*) FROM sources WHERE status='error'"
                ).fetchone()[0],
                "last_run": dict(row)
                if (
                    row := db.execute(
                        "SELECT topic,started,metrics FROM runs ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                )
                else None,
            }
