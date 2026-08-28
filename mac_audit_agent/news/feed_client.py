from __future__ import annotations

import logging
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .models import NewsSettings
from .security import ALLOWED_ARTICLE_HOSTS, ALLOWED_FEED_HOSTS, valid_feed_url

LOGGER = logging.getLogger(__name__)
ALLOWED_FEED_REDIRECT_HOSTS = ALLOWED_FEED_HOSTS | ALLOWED_ARTICLE_HOSTS


class FeedClientError(RuntimeError):
    pass


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, maximum_redirects: int) -> None:
        super().__init__()
        self.maximum_redirects = maximum_redirects

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        target = urlsplit(urljoin(request.full_url, new_url))
        count = int(request.headers.get("X-MSAA-Redirect-Count", "0")) + 1
        if (
            count > self.maximum_redirects or target.scheme != "https"
            or (target.hostname or "").rstrip(".").lower() not in ALLOWED_FEED_REDIRECT_HOSTS
            or target.username is not None or target.password is not None or target.port not in (None, 443)
        ):
            raise FeedClientError("feed redirect was rejected")
        redirected = super().redirect_request(request, file_pointer, code, message, headers, target.geturl())
        if redirected is not None:
            redirected.add_header("X-MSAA-Redirect-Count", str(count))
        return redirected


@dataclass(frozen=True)
class FeedResponse:
    payload: bytes
    final_url: str


class THNFeedClient:
    def __init__(self, settings: NewsSettings = NewsSettings(), *, opener=None, sleeper=time.sleep, clock=time.monotonic) -> None:
        if not valid_feed_url(settings.feed_url):
            raise ValueError("The configured news feed endpoint is not allowlisted")
        self.settings = settings
        self._sleep = sleeper
        self._clock = clock
        context = ssl.create_default_context()
        self._opener = opener or urllib.request.build_opener(
            _BoundedRedirectHandler(settings.maximum_redirects), urllib.request.HTTPSHandler(context=context)
        )

    def fetch(self) -> FeedResponse:
        deadline = self._clock() + self.settings.total_timeout_seconds
        last_error: Exception | None = None
        for attempt in range(self.settings.retries + 1):
            if self._clock() >= deadline:
                break
            request = urllib.request.Request(
                self.settings.feed_url,
                headers={"User-Agent": "MSAA-Threat-News/1.0", "Accept": "application/rss+xml, application/xml;q=0.9", "Connection": "close"},
                method="GET",
            )
            try:
                timeout = max(0.1, min(self.settings.connect_timeout_seconds, deadline - self._clock()))
                with self._opener.open(request, timeout=timeout) as response:
                    final = urlsplit(response.geturl())
                    if final.scheme != "https" or (final.hostname or "").rstrip(".").lower() not in ALLOWED_FEED_REDIRECT_HOSTS:
                        raise FeedClientError("feed response origin was rejected")
                    status = int(getattr(response, "status", 200))
                    if status != 200:
                        raise FeedClientError(f"feed returned HTTP {status}")
                    content_type = str(response.headers.get("Content-Type", "")).lower()
                    if content_type and not any(value in content_type for value in ("xml", "rss", "atom", "text/plain")):
                        raise FeedClientError("feed content type was rejected")
                    chunks: list[bytes] = []
                    total = 0
                    while True:
                        if self._clock() >= deadline:
                            raise FeedClientError("feed request exceeded total timeout")
                        chunk = response.read(min(65536, self.settings.maximum_response_bytes + 1 - total))
                        if not chunk: break
                        total += len(chunk)
                        if total > self.settings.maximum_response_bytes:
                            raise FeedClientError("feed exceeded maximum response size")
                        chunks.append(chunk)
                    return FeedResponse(b"".join(chunks), response.geturl())
            except (FeedClientError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ssl.SSLError) as exc:
                last_error = exc
                if attempt < self.settings.retries and self._clock() < deadline:
                    self._sleep(min(0.5 * (2 ** attempt), max(0.0, deadline - self._clock())))
        raise FeedClientError("The Hacker News feed could not be retrieved") from last_error
