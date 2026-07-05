from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.nmap_wrapper import find_nmap_binary
from mac_audit_agent.network_intelligence.models import NetworkIntelligenceSnapshot

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class NetworkDiagnosticsErrorContext:
    snapshot_id: str
    function_called: str
    invalid_kwargs: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_network_intelligence_diagnostics(
    snapshot: NetworkIntelligenceSnapshot | None = None,
    *,
    settings: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if kwargs:
        context = NetworkDiagnosticsErrorContext(
            snapshot_id=str(getattr(snapshot, "snapshot_id", "")),
            function_called="build_network_intelligence_diagnostics",
            invalid_kwargs=dict(kwargs),
        )
        LOGGER.warning("Unexpected diagnostic kwargs received: %s", context.to_dict())
    settings = settings or {}
    extra = extra if isinstance(extra, dict) else {}
    diagnostics = dict(snapshot.diagnostics if snapshot else {})
    errors = diagnostics.get("errors", [])
    if not isinstance(errors, list):
        errors = [str(errors)]
    payload = {
        "module_loaded": True,
        "collectors_running": bool(snapshot),
        "last_scan_time": getattr(snapshot, "timestamp", "") if snapshot else "",
        "last_error": "; ".join(str(item) for item in errors) if errors else "",
        "db_write_success": bool(diagnostics.get("db_write_success", False)),
        "alert_pipeline_success": bool(diagnostics.get("alert_pipeline_success", False)),
        "ui_tab_loading_success": True,
        "permissions_status": "read-only collectors",
        "network_activity_monitoring_enabled": bool(settings.get("network_activity_monitoring_enabled", True)),
        "nmap_installed": bool(find_nmap_binary()),
        "nmap_path": find_nmap_binary() or "",
        "collector_counts": {
            "connections": len(getattr(snapshot, "connections", []) or []) if snapshot else 0,
            "listeners": len(getattr(snapshot, "listeners", []) or []) if snapshot else 0,
            "findings": len(getattr(snapshot, "findings", []) or []) if snapshot else 0,
        },
        "errors": errors,
    }
    for key, value in extra.items():
        if key in {
            "db_write_success",
            "alert_pipeline_success",
            "normalized_event_count",
            "ui_tab_loading_success",
            "permissions_status",
            "last_error",
            "failure_stage",
        }:
            payload[key] = value
        else:
            payload.setdefault("extra", {})[key] = value
    return payload
