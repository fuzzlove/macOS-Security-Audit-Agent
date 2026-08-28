from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .feed_client import THNFeedClient
from .feed_parser import parse_thn_feed
from .models import NewsSettings
from .repository import NewsRepository

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RefreshResult:
    received: int
    valid: int
    rejected: int
    cached: int
    refreshed_at: datetime


class NewsRefreshCoordinator:
    """Single-flight, rate-limited feed refresh shared by GUI and tests."""

    def __init__(self, repository: NewsRepository, settings: NewsSettings, client_factory=THNFeedClient, clock=time.monotonic) -> None:
        self.repository = repository
        self.settings = settings
        self.client_factory = client_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._running = False
        self._last_attempt = float("-inf")

    def begin(self, manual: bool = True) -> tuple[bool, str]:
        with self._lock:
            now = self._clock()
            if not self.settings.enabled:
                return False, "External news access is disabled."
            if self._running:
                return False, "A feed refresh is already running."
            if manual and now - self._last_attempt < self.settings.manual_refresh_interval_seconds:
                return False, "Please wait before refreshing the feed again."
            self._running = True
            self._last_attempt = now
            return True, ""

    def finish(self) -> None:
        with self._lock: self._running = False

    def refresh(self, protected_article_id: str | None = None) -> RefreshResult:
        LOGGER.info("thn_news_refresh_started")
        now = datetime.now(timezone.utc)
        try:
            response = self.client_factory(self.settings).fetch()
            articles, rejected = parse_thn_feed(response.payload, now, self.settings)
            cached = self.repository.upsert(articles)
            self.repository.set_last_successful_refresh(now)
            self.repository.cleanup(self.settings, protected_article_id, now)
            LOGGER.info(
                "thn_news_refresh_completed received=%d valid=%d rejected=%d cached=%d refreshed_at=%s",
                len(articles) + rejected, len(articles), rejected, cached, now.isoformat(),
            )
            return RefreshResult(len(articles) + rejected, len(articles), rejected, cached, now)
        except Exception as exc:
            LOGGER.warning("thn_news_refresh_failed error_type=%s", type(exc).__name__)
            raise
        finally:
            self.finish()
