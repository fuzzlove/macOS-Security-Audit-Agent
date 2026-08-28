from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.ui.findings_filter import normalize_severity


@dataclass(frozen=True)
class NavigationIntent:
    target_view: str
    filter_type: str
    filter_value: str
    source: str
    scan_id: str | None = None
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_route(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.filter_type and self.filter_value:
            params[self.filter_type] = self.filter_value
        if self.scan_id:
            params["scan_id"] = self.scan_id
        return {"view": self.target_view, "params": params}

    def to_internal_url(self) -> str:
        params = [f"{self.filter_type}={self.filter_value}"] if self.filter_type and self.filter_value else []
        if self.scan_id:
            params.append(f"scan_id={self.scan_id}")
        return "msaa://findings" + (("?" + "&".join(params)) if params else "")


def create_findings_severity_intent(severity: str, scan_id: str | None = None, source: str = "dashboard") -> NavigationIntent:
    normalized = normalize_severity(severity)
    return NavigationIntent(
        target_view="findings",
        filter_type="severity",
        filter_value=normalized,
        source=source,
        scan_id=scan_id,
    )


__all__ = ["NavigationIntent", "create_findings_severity_intent"]
