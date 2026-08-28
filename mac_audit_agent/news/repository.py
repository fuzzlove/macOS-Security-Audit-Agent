from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from mac_audit_agent.storage import AuditDatabase

from .models import NewsArticle, NewsFilterMode, NewsSettings

LOGGER = logging.getLogger(__name__)


class NewsRepository:
    """News cache stored in MSAA's existing audit database."""

    def __init__(self, database: AuditDatabase) -> None:
        self.database = database
        self.conn = database.conn
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS news_cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS news_articles (
                article_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                guid TEXT,
                title TEXT NOT NULL,
                canonical_url TEXT NOT NULL,
                summary_text TEXT NOT NULL,
                author TEXT,
                categories_json TEXT NOT NULL,
                published_at_utc TEXT NOT NULL,
                fetched_at_utc TEXT NOT NULL,
                source_feed_url TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                malware_relevant INTEGER NOT NULL,
                validation_status TEXT NOT NULL,
                bookmarked INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_news_articles_url ON news_articles(canonical_url);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_news_articles_guid ON news_articles(guid) WHERE guid IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_news_articles_published ON news_articles(published_at_utc DESC);
            INSERT OR IGNORE INTO news_cache_meta(key, value) VALUES ('schema_version', '1');
        """)
        self.conn.commit()

    def upsert(self, articles: list[NewsArticle]) -> int:
        new_count = 0
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            for article in articles:
                # URL identity wins when a publisher changes a GUID; GUID identity wins when metadata changes.
                row = self.conn.execute(
                    "SELECT article_id FROM news_articles WHERE canonical_url = ? OR (? IS NOT NULL AND guid = ?) LIMIT 1",
                    (article.canonical_url, article.guid, article.guid),
                ).fetchone()
                article_id = str(row["article_id"]) if row else article.article_id
                if row is None:
                    new_count += 1
                self.conn.execute("""
                    INSERT INTO news_articles (
                        article_id, source, guid, title, canonical_url, summary_text, author, categories_json,
                        published_at_utc, fetched_at_utc, source_feed_url, content_hash, malware_relevant, validation_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(article_id) DO UPDATE SET
                        source=excluded.source, guid=COALESCE(excluded.guid, news_articles.guid), title=excluded.title,
                        canonical_url=excluded.canonical_url, summary_text=excluded.summary_text, author=excluded.author,
                        categories_json=excluded.categories_json, published_at_utc=excluded.published_at_utc,
                        fetched_at_utc=excluded.fetched_at_utc, source_feed_url=excluded.source_feed_url,
                        content_hash=excluded.content_hash, malware_relevant=excluded.malware_relevant,
                        validation_status=excluded.validation_status
                """, (
                    article_id, article.source, article.guid, article.title, article.canonical_url,
                    article.summary_text, article.author, json.dumps(article.categories),
                    article.published_at_utc.isoformat(), article.fetched_at_utc.isoformat(), article.source_feed_url,
                    article.content_hash, int(article.malware_relevant), article.validation_status,
                ))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            LOGGER.exception("thn_news_cache_failure operation=upsert")
            raise
        return new_count

    def list_articles(self, mode: NewsFilterMode) -> list[NewsArticle]:
        where = "WHERE validation_status = 'VALID'"
        if mode == NewsFilterMode.MALWARE_FOCUSED:
            where += " AND malware_relevant = 1"
        rows = self.conn.execute(f"SELECT * FROM news_articles {where} ORDER BY published_at_utc DESC, article_id ASC").fetchall()
        return [self._article(row) for row in rows]

    def get(self, article_id: str) -> NewsArticle | None:
        row = self.conn.execute("SELECT * FROM news_articles WHERE article_id = ? AND validation_status = 'VALID'", (article_id,)).fetchone()
        return self._article(row) if row else None

    def set_last_successful_refresh(self, when: datetime) -> None:
        self.conn.execute(
            "INSERT INTO news_cache_meta(key, value) VALUES ('last_successful_refresh', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (when.astimezone(timezone.utc).isoformat(),),
        )
        self.conn.commit()

    def last_successful_refresh(self) -> datetime | None:
        row = self.conn.execute("SELECT value FROM news_cache_meta WHERE key = 'last_successful_refresh'").fetchone()
        if not row: return None
        try: return datetime.fromisoformat(str(row["value"])).astimezone(timezone.utc)
        except ValueError: return None

    def cleanup(self, settings: NewsSettings, protected_article_id: str | None = None, now: datetime | None = None) -> int:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        protected = protected_article_id or ""
        before = self.conn.total_changes
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute(
                "DELETE FROM news_articles WHERE bookmarked = 0 AND article_id != ? AND published_at_utc < ?",
                (protected, (now - timedelta(days=settings.maximum_age_days)).isoformat()),
            )
            excess = self.conn.execute("SELECT MAX(COUNT(*) - ?, 0) AS amount FROM news_articles WHERE validation_status = 'VALID'", (settings.maximum_articles,)).fetchone()
            amount = int(excess["amount"] or 0)
            if amount:
                self.conn.execute("""
                    DELETE FROM news_articles WHERE article_id IN (
                        SELECT article_id FROM news_articles
                        WHERE validation_status = 'VALID' AND bookmarked = 0 AND article_id != ?
                        ORDER BY published_at_utc ASC LIMIT ?
                    )
                """, (protected, amount))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return max(0, self.conn.total_changes - before)

    @staticmethod
    def _article(row) -> NewsArticle:
        try: categories = tuple(str(value) for value in json.loads(row["categories_json"]))
        except (TypeError, ValueError, json.JSONDecodeError): categories = ()
        return NewsArticle(
            article_id=row["article_id"], source=row["source"], guid=row["guid"], title=row["title"],
            canonical_url=row["canonical_url"], summary_text=row["summary_text"], author=row["author"],
            categories=categories, published_at_utc=datetime.fromisoformat(row["published_at_utc"]).astimezone(timezone.utc),
            fetched_at_utc=datetime.fromisoformat(row["fetched_at_utc"]).astimezone(timezone.utc),
            source_feed_url=row["source_feed_url"], content_hash=row["content_hash"],
            malware_relevant=bool(row["malware_relevant"]), validation_status=row["validation_status"],
        )
