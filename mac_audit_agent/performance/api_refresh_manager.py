from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.performance.resource_budget import ResourceBudget, load_resource_budget


@dataclass
class ApiRefreshResult:
    source_id: str
    status: str
    payload: Any = None
    used_cache: bool = False
    stale: bool = False
    error: str = ""
    started_at: str = ""
    completed_at: str = ""
    diagnostic_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApiRefreshManager:
    def __init__(self, budget: ResourceBudget | None = None, cache_get: Callable[[str], Any] | None = None, cache_set: Callable[[str, Any], None] | None = None) -> None:
        self.budget = budget or load_resource_budget()
        self.cache_get = cache_get
        self.cache_set = cache_set
        self._last_request_times: list[float] = []
        self._circuit_open_until: dict[str, float] = {}

    def _rate_limit(self) -> None:
        now = time.monotonic()
        self._last_request_times = [item for item in self._last_request_times if now - item < 60]
        if len(self._last_request_times) >= self.budget.max_api_requests_per_minute:
            sleep_for = max(0.0, 60 - (now - self._last_request_times[0]))
            time.sleep(min(sleep_for, 2.0))
        self._last_request_times.append(time.monotonic())

    def refresh(
        self,
        source_id: str,
        fetcher: Callable[[], Any],
        *,
        force: bool = False,
        ttl_seconds: int = 86_400,
        max_records: int | None = None,
    ) -> ApiRefreshResult:
        started = utc_now_iso()
        now = time.monotonic()
        if self._circuit_open_until.get(source_id, 0) > now and not force:
            cached = self.cache_get(source_id) if self.cache_get else None
            return ApiRefreshResult(source_id, "circuit_open_cache", cached, used_cache=True, stale=True, started_at=started, completed_at=utc_now_iso(), error="API circuit breaker open.")
        if not force and self.cache_get:
            cached = self.cache_get(source_id)
            if isinstance(cached, dict):
                age = float(cached.get("_cache_age_seconds", ttl_seconds + 1) or 0)
                if age <= ttl_seconds:
                    return ApiRefreshResult(source_id, "cache_fresh", cached.get("payload", cached), used_cache=True, started_at=started, completed_at=utc_now_iso())
        try:
            self._rate_limit()
            payload = fetcher()
            if max_records is not None and isinstance(payload, list):
                payload = payload[:max_records]
            if self.cache_set:
                self.cache_set(source_id, {"payload": payload, "stored_at": utc_now_iso(), "_cache_age_seconds": 0})
            return ApiRefreshResult(source_id, "updated", payload, started_at=started, completed_at=utc_now_iso())
        except Exception as exc:  # noqa: BLE001
            self._circuit_open_until[source_id] = time.monotonic() + 300
            cached = self.cache_get(source_id) if self.cache_get else None
            return ApiRefreshResult(source_id, "failed_cache" if cached is not None else "failed", cached, used_cache=cached is not None, stale=cached is not None, error=str(exc), started_at=started, completed_at=utc_now_iso())


def fetch_url_bytes(url: str, *, timeout_seconds: int | None = None, headers: dict[str, str] | None = None, max_bytes: int = 10 * 1024 * 1024) -> bytes:
    budget = load_resource_budget()
    request = urllib.request.Request(url, headers=headers or {"User-Agent": "MSAA bounded refresh"})
    with urllib.request.urlopen(request, timeout=timeout_seconds or budget.api_timeout_seconds) as response:  # noqa: S310
        payload = response.read(max(1, max_bytes) + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"NET001: response exceeded the {max_bytes}-byte safety limit")
    return payload
