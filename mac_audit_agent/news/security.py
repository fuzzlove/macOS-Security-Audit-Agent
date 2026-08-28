from __future__ import annotations

import hashlib
import html
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

ALLOWED_ARTICLE_HOSTS = frozenset({"thehackernews.com", "www.thehackernews.com"})
ALLOWED_FEED_HOSTS = frozenset({"feeds.feedburner.com"})
ARTICLE_PATH = re.compile(r"^/20\d{2}/(?:0[1-9]|1[0-2])/[a-z0-9][a-z0-9-]*\.html$")
PROMOTIONAL_TERMS = re.compile(r"\b(webinar|whitepaper|e-?book|download now|register now|sponsored)\b", re.I)
TRACKING_PARAMETERS = frozenset({"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"})


def normalize_article_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
        hostname = (parsed.hostname or "").rstrip(".").lower().encode("ascii").decode("ascii")
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        if parsed.port not in (None, 443) or hostname not in ALLOWED_ARTICLE_HOSTS:
            return None
        try:
            ipaddress.ip_address(hostname)
            return None
        except ValueError:
            pass
        if not ARTICLE_PATH.fullmatch(parsed.path):
            return None
        return urlunsplit(("https", hostname, parsed.path, "", ""))
    except (UnicodeError, ValueError):
        return None


def valid_feed_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https" and parsed.hostname in ALLOWED_FEED_HOSTS
            and parsed.username is None and parsed.password is None and parsed.port in (None, 443)
            and parsed.path == "/TheHackersNews" and not parsed.query and not parsed.fragment
        )
    except ValueError:
        return False


class _PlainTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in {"script", "style", "iframe", "object", "embed", "svg", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "iframe", "object", "embed", "svg", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def plain_text(value: str, maximum: int) -> str:
    parser = _PlainTextExtractor()
    try:
        parser.feed(value[: max(maximum * 20, 4096)])
        parser.close()
        text = " ".join(parser.parts)
    except (ValueError, RecursionError):
        text = re.sub(r"<[^>]*>", " ", value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", html.unescape(text))
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.;:!?])", r"\1", text)
    if len(text) > maximum:
        text = text[: max(0, maximum - 1)].rstrip() + "…"
    return text


def content_digest(*values: str) -> str:
    return hashlib.sha256("\x1f".join(values).encode("utf-8", "replace")).hexdigest()
