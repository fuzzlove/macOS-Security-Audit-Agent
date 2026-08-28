from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class NewsFilterMode(str, Enum):
    MALWARE_FOCUSED = "Malware Focused"
    ALL_CYBERSECURITY = "All Cybersecurity News"


@dataclass(frozen=True)
class NewsSettings:
    feed_url: str = "https://feeds.feedburner.com/TheHackersNews"
    enabled: bool = True
    show_cache_when_disabled: bool = True
    automatic_refresh: bool = False
    automatic_refresh_minutes: int = 60
    auto_advance_latest: bool = False
    filter_mode: NewsFilterMode = NewsFilterMode.MALWARE_FOCUSED
    maximum_articles: int = 500
    maximum_age_days: int = 180
    connect_timeout_seconds: float = 5.0
    total_timeout_seconds: float = 15.0
    maximum_response_bytes: int = 2 * 1024 * 1024
    maximum_redirects: int = 3
    retries: int = 2
    manual_refresh_interval_seconds: float = 30.0
    maximum_summary_characters: int = 600


@dataclass(frozen=True)
class NewsArticle:
    article_id: str
    source: str
    guid: str | None
    title: str
    canonical_url: str
    summary_text: str
    author: str | None
    categories: tuple[str, ...]
    published_at_utc: datetime
    fetched_at_utc: datetime
    source_feed_url: str
    content_hash: str
    malware_relevant: bool
    validation_status: str = "VALID"
