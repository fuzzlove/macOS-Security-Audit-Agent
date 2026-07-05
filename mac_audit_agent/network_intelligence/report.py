from __future__ import annotations

from typing import Any

from mac_audit_agent.network_intelligence.models import NetworkIntelligenceSnapshot


def build_network_intelligence_report(snapshot: NetworkIntelligenceSnapshot | None) -> dict[str, Any]:
    if snapshot is None:
        return {
            "section": "Network Intelligence",
            "summary": {
                "status": "not_collected",
                "active_connections": 0,
                "listening_ports": 0,
                "findings": 0,
                "highest_risk": "unknown",
            },
            "connections": [],
            "listeners": [],
            "posture": {},
            "findings": [],
            "baseline_drift": {},
            "diagnostics": {"last_error": "Network Intelligence has not run yet."},
        }
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest = max((finding.severity for finding in snapshot.findings), key=lambda value: severity_order.get(value, 0), default="info")
    return {
        "section": "Network Intelligence",
        "summary": {
            "status": "ok" if not snapshot.diagnostics.get("errors") else "degraded",
            "active_connections": len(snapshot.connections),
            "listening_ports": len(snapshot.listeners),
            "findings": len(snapshot.findings),
            "highest_risk": highest,
            "last_scan_time": snapshot.timestamp,
            "baseline_drift_status": snapshot.baseline_comparison.get("status", "unknown"),
        },
        "connections": [item.to_dict() for item in snapshot.connections],
        "listeners": [item.to_dict() for item in snapshot.listeners],
        "posture": snapshot.posture.to_dict(),
        "findings": [item.to_dict() for item in snapshot.findings],
        "baseline_drift": dict(snapshot.baseline_comparison),
        "diagnostics": dict(snapshot.diagnostics),
    }
