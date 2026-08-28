from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from mac_audit_agent.models import utc_now_iso


@dataclass
class CachedPanelPayload:
    panel_id: str
    payload: dict[str, Any]
    generated_at: str
    stale: bool = False
    source: str = "cache"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LoadingState:
    panel_id: str
    message: str = "Loading..."
    started_at: str = field(default_factory=utc_now_iso)


@dataclass
class ErrorState:
    panel_id: str
    message: str
    error_type: str = ""
    occurred_at: str = field(default_factory=utc_now_iso)


@dataclass
class RefreshState:
    panel_id: str
    running: bool = False
    last_refresh_at: str = ""
    stale: bool = False
    error: str = ""


class LazyPanelLoader:
    def __init__(self) -> None:
        self._loaded: dict[str, CachedPanelPayload] = {}

    def get_cached(self, panel_id: str) -> CachedPanelPayload | None:
        return self._loaded.get(panel_id)

    def load_once(self, panel_id: str, loader: Callable[[], dict[str, Any]], *, source: str = "lazy") -> CachedPanelPayload:
        cached = self._loaded.get(panel_id)
        if cached is not None:
            return cached
        payload = loader()
        cached = CachedPanelPayload(panel_id=panel_id, payload=payload, generated_at=utc_now_iso(), source=source)
        self._loaded[panel_id] = cached
        return cached

    def invalidate(self, panel_id: str) -> None:
        self._loaded.pop(panel_id, None)
