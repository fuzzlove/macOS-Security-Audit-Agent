from __future__ import annotations

import os
import random
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QSizePolicy

from mac_audit_agent.news.feed_parser import FeedParseError, parse_thn_feed
from mac_audit_agent.news.feed_client import FeedClientError, THNFeedClient
from mac_audit_agent.news.models import NewsArticle, NewsFilterMode, NewsSettings
from mac_audit_agent.news.navigation import NewsNavigator
from mac_audit_agent.news.repository import NewsRepository
from mac_audit_agent.news.security import normalize_article_url, plain_text
from mac_audit_agent.news.service import NewsRefreshCoordinator
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.threat_news_widget import ThreatNewsWidget

FIXTURE = Path(__file__).parent / "fixtures" / "thn_feed.xml"
NOW = datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc)


@pytest.fixture
def repository(tmp_path: Path):
    database = AuditDatabase(tmp_path / "audit.sqlite3", tmp_path / "logs")
    repo = NewsRepository(database)
    yield repo
    database.close()


def articles() -> list[NewsArticle]:
    parsed, _ = parse_thn_feed(FIXTURE.read_bytes(), NOW)
    return parsed


def test_valid_feed_is_sanitized_normalized_and_classified() -> None:
    parsed, rejected = parse_thn_feed(FIXTURE.read_bytes(), NOW)
    assert rejected == 0 and len(parsed) == 3
    assert parsed[0].published_at_utc == datetime(2026, 7, 19, 14, 30, tzinfo=timezone.utc)
    assert parsed[1].published_at_utc == datetime(2026, 7, 18, 13, 15, tzinfo=timezone.utc)
    assert parsed[0].canonical_url == "https://thehackernews.com/2026/07/new-macos-malware.html"
    assert parsed[0].summary_text == "Researchers describe a new backdoor affecting endpoints. Details."
    assert parsed[0].categories == ("Malware", "Threat Intelligence")
    assert parsed[0].malware_relevant is True
    assert parsed[2].malware_relevant is False


def test_entries_are_stored_once_and_metadata_is_merged(repository: NewsRepository) -> None:
    original = articles()[0]
    assert repository.upsert([original, original]) == 1
    updated = replace(original, title="Updated publisher headline", content_hash="new-hash")
    assert repository.upsert([updated]) == 0
    stored = repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY)
    assert len(stored) == 1
    assert stored[0].article_id == original.article_id
    assert stored[0].title == "Updated publisher headline"


def test_repository_filters_and_applies_bounded_retention(repository: NewsRepository) -> None:
    values = articles(); repository.upsert(values)
    assert len(repository.list_articles(NewsFilterMode.MALWARE_FOCUSED)) == 2
    assert len(repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY)) == 3
    protected = values[-1].article_id
    repository.cleanup(replace(NewsSettings(), maximum_articles=1, maximum_age_days=1), protected, NOW + timedelta(days=3))
    remaining = repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY)
    assert [article.article_id for article in remaining] == [protected]


def test_chronological_navigation_and_boundaries() -> None:
    navigator = NewsNavigator(); values = articles(); navigator.replace(values)
    assert navigator.current == values[0] and not navigator.can_newer and navigator.can_older
    assert navigator.older() == values[1] and navigator.can_newer and navigator.can_older
    assert navigator.older() == values[2] and navigator.can_newer and not navigator.can_older
    assert navigator.newer() == values[1]
    assert navigator.latest() == values[0]


def test_surprise_does_not_repeat_and_keeps_chronological_position() -> None:
    navigator = NewsNavigator(random.Random(7)); values = articles(); navigator.replace(values)
    first = navigator.current
    selected = navigator.surprise()
    assert selected in values and selected != first
    position = values.index(selected)
    assert navigator.can_newer == (position > 0)
    assert navigator.can_older == (position < len(values) - 1)


@pytest.mark.parametrize("url", [
    "https://thehackernews.com.attacker.example/2026/07/a.html",
    "https://attacker.example/thehackernews.com/2026/07/a.html",
    "http://thehackernews.com/2026/07/a.html",
    "https://user@thehackernews.com/2026/07/a.html",
    "https://thehackernews.com:8443/2026/07/a.html",
    "https://thehackernews.uk/2026/07/a.html",
    "https://127.0.0.1/2026/07/a.html",
    "file:///etc/passwd", "javascript:alert(1)",
    "https://thehackernews.com/webinar/register.html",
])
def test_malicious_article_urls_are_rejected(url: str) -> None:
    assert normalize_article_url(url) is None


def test_only_normal_thn_article_url_is_accepted() -> None:
    assert normalize_article_url("https://www.thehackernews.com/2026/07/real-story.html?utm_source=x") == "https://www.thehackernews.com/2026/07/real-story.html"


@pytest.mark.parametrize("payload", [
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><rss><item>&e;</item></rss>',
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "123"><!ENTITY b "&a;&a;">]><rss>&b;</rss>',
    b'<?xml version="1.0" encoding="ISO-8859-1"?><rss/>',
    b'<rss><channel><item></channel></rss>',
    (b'<a>' * 40) + (b'</a>' * 40),
])
def test_malicious_xml_is_safely_rejected(payload: bytes) -> None:
    with pytest.raises(FeedParseError): parse_thn_feed(payload, NOW)


def test_oversized_xml_and_missing_fields_are_rejected() -> None:
    settings = replace(NewsSettings(), maximum_response_bytes=50)
    with pytest.raises(FeedParseError): parse_thn_feed(b"<rss>" + b"x" * 60 + b"</rss>", NOW, settings)
    parsed, rejected = parse_thn_feed(b"<rss><channel><item><title>Only title</title></item></channel></rss>", NOW)
    assert parsed == [] and rejected == 1


def test_malicious_html_becomes_bounded_plain_text() -> None:
    markup = '<script>alert(1)</script><style>x</style><iframe>bad</iframe><svg>pixel</svg><p onclick="x">Safe &amp; useful</p><img src="data:x"><a href="javascript:x">link</a>' + ("Z" * 1000)
    result = plain_text(markup, 80)
    assert result.startswith("Safe & useful link") and result.endswith("…")
    assert all(term not in result for term in ("alert", "bad", "pixel", "javascript", "data:"))
    assert len(result) == 80


def test_refresh_is_single_flight_rate_limited_and_privacy_aware(repository: NewsRepository) -> None:
    clock = [100.0]
    coordinator = NewsRefreshCoordinator(repository, NewsSettings(), clock=lambda: clock[0])
    assert coordinator.begin() == (True, "")
    assert coordinator.begin()[0] is False
    coordinator.finish()
    assert coordinator.begin()[0] is False
    clock[0] += 31
    assert coordinator.begin()[0] is True
    coordinator.finish()
    disabled = NewsRefreshCoordinator(repository, replace(NewsSettings(), enabled=False), client_factory=lambda _: pytest.fail("network used"))
    assert disabled.begin()[0] is False


def test_feed_client_bounds_response_and_sends_no_cookie() -> None:
    class Response:
        status = 200
        headers = {"Content-Type": "application/rss+xml"}
        def __init__(self, payload: bytes, url: str): self.payload = payload; self.url = url; self.offset = 0
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def geturl(self): return self.url
        def read(self, amount):
            value = self.payload[self.offset:self.offset + amount]; self.offset += len(value); return value
    class Opener:
        def __init__(self, response): self.response = response; self.request = None
        def open(self, request, timeout): self.request = request; return self.response
    settings = replace(NewsSettings(), maximum_response_bytes=20, retries=0)
    opener = Opener(Response(b"x" * 21, settings.feed_url))
    with pytest.raises(FeedClientError): THNFeedClient(settings, opener=opener).fetch()
    assert opener.request.get_header("Cookie") is None
    assert opener.request.get_header("User-agent") == "MSAA-Threat-News/1.0"


def test_feed_client_rejects_unauthorized_final_origin() -> None:
    class Response:
        status = 200; headers = {"Content-Type": "application/rss+xml"}
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def geturl(self): return "https://attacker.example/feed.xml"
    class Opener:
        def open(self, request, timeout): return Response()
    with pytest.raises(FeedClientError): THNFeedClient(replace(NewsSettings(), retries=0), opener=Opener()).fetch()


def test_offline_failure_keeps_cached_articles(repository: NewsRepository) -> None:
    repository.upsert(articles())
    before = repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY)
    class FailedClient:
        def __init__(self, settings): pass
        def fetch(self): raise OSError("offline")
    coordinator = NewsRefreshCoordinator(repository, NewsSettings(), client_factory=FailedClient)
    assert coordinator.begin()[0]
    with pytest.raises(OSError): coordinator.refresh(before[0].article_id)
    assert repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY) == before


def test_privacy_disabled_widget_uses_cache_without_starting_network(repository: NewsRepository) -> None:
    app = QApplication.instance() or QApplication([])
    repository.upsert(articles())
    settings = QSettings("MSAA", "ThreatNews"); settings.clear(); settings.setValue("enabled", False)
    widget = ThreatNewsWidget(repository.database)
    assert widget.navigator.current is not None
    assert widget.refresh_button.isEnabled() is False
    assert "External news access disabled" in widget.cache_label.text()
    assert widget._thread is None
    assert widget.title() == "Current Malware & Threat News"
    assert widget.read_button.text() == "Read Original Article"
    assert widget.older_button.isEnabled()
    widget.close(); settings.clear(); app.processEvents()


def test_feed_status_is_full_width_wrapping_and_not_constrained_by_refresh_button(repository: NewsRepository) -> None:
    app = QApplication.instance() or QApplication([])
    settings = QSettings("MSAA", "ThreatNews"); settings.clear()
    widget = ThreatNewsWidget(repository.database)

    assert widget.feed_status_group.title() == "Feed status"
    assert widget.layout().indexOf(widget.feed_status_group) >= 0
    assert widget.layout().indexOf(widget.refresh_button) > widget.layout().indexOf(widget.feed_status_group)
    for label in (widget.cache_label, widget.status_label):
        assert label.wordWrap()
        assert label.minimumWidth() == 0
        assert label.sizePolicy().horizontalPolicy() == QSizePolicy.Expanding
        assert label.sizePolicy().verticalPolicy() == QSizePolicy.Minimum

    widget._refresh_failed("MSAA could not retrieve the feed because the network connection timed out.")
    assert "timed out" in widget.status_label.text()
    assert "Offline" in widget.cache_label.text() or widget.navigator.current is None

    widget.close(); settings.clear(); app.processEvents()
