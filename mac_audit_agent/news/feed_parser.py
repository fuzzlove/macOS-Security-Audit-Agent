from __future__ import annotations

import io
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .models import NewsArticle, NewsSettings
from .relevance import is_malware_relevant
from .security import PROMOTIONAL_TERMS, content_digest, normalize_article_url, plain_text

LOGGER = logging.getLogger(__name__)
FORBIDDEN_XML = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
ALLOWED_ENCODINGS = frozenset({"utf-8", "utf8", "us-ascii", "ascii"})


class FeedParseError(ValueError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _text(element: ET.Element, names: set[str], maximum: int = 10000) -> str:
    for child in element:
        if _local(child.tag) in names:
            return "".join(child.itertext())[:maximum].strip()
    return ""


def _date(value: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None


def parse_thn_feed(payload: bytes, fetched_at: datetime, settings: NewsSettings = NewsSettings()) -> tuple[list[NewsArticle], int]:
    if not payload or len(payload) > settings.maximum_response_bytes:
        raise FeedParseError("feed size is invalid")
    if FORBIDDEN_XML.search(payload):
        raise FeedParseError("DTD and entity declarations are prohibited")
    declaration = re.match(br"\s*<\?xml[^>]*encoding=['\"]([^'\"]+)", payload, re.I)
    if declaration and declaration.group(1).decode("ascii", "ignore").lower() not in ALLOWED_ENCODINGS:
        raise FeedParseError("unsupported feed encoding")
    try:
        depth = 0
        root = None
        for event, element in ET.iterparse(io.BytesIO(payload), events=("start", "end")):
            if event == "start":
                depth += 1
                if depth > 32:
                    raise FeedParseError("feed nesting limit exceeded")
                if len(element.attrib) > 32:
                    raise FeedParseError("attribute limit exceeded")
                if root is None:
                    root = element
            else:
                depth -= 1
    except (ET.ParseError, UnicodeError, RecursionError) as exc:
        raise FeedParseError("feed XML is malformed") from exc
    if root is None:
        raise FeedParseError("feed XML is empty")

    articles: list[NewsArticle] = []
    rejected = 0
    seen_guid: set[str] = set()
    seen_url: set[str] = set()
    for item in (node for node in root.iter() if _local(node.tag) in {"item", "entry"}):
        title = plain_text(_text(item, {"title"}, 1000), 300)
        guid = plain_text(_text(item, {"guid", "id"}, 2000), 1000) or None
        link = _text(item, {"link"}, 4000)
        if not link:
            for child in item:
                if _local(child.tag) == "link" and child.attrib.get("href"):
                    link = child.attrib["href"]
                    break
        canonical = normalize_article_url(link)
        published = _date(_text(item, {"pubdate", "published", "updated"}, 500))
        raw_summary = _text(item, {"description", "summary", "encoded"}, settings.maximum_summary_characters * 20)
        summary = plain_text(raw_summary, settings.maximum_summary_characters)
        categories = tuple(dict.fromkeys(plain_text("".join(node.itertext()), 100) for node in item if _local(node.tag) == "category" and "".join(node.itertext()).strip()))
        author = plain_text(_text(item, {"author", "creator"}, 500), 200) or None
        if not title or not canonical or published is None or (not guid and not canonical) or not summary:
            rejected += 1; continue
        if PROMOTIONAL_TERMS.search(" ".join((title, summary, *categories))):
            rejected += 1; continue
        if guid in seen_guid or canonical in seen_url:
            rejected += 1; continue
        if guid: seen_guid.add(guid)
        seen_url.add(canonical)
        digest = content_digest(title, canonical, summary, published.isoformat(), *categories)
        articles.append(NewsArticle(
            article_id=content_digest(guid or canonical)[:32], source="The Hacker News", guid=guid,
            title=title, canonical_url=canonical, summary_text=summary, author=author, categories=categories,
            published_at_utc=published, fetched_at_utc=fetched_at.astimezone(timezone.utc),
            source_feed_url=settings.feed_url, content_hash=digest,
            malware_relevant=is_malware_relevant(title, summary, categories), validation_status="VALID",
        ))
    articles.sort(key=lambda article: (article.published_at_utc, article.article_id), reverse=True)
    return articles, rejected
