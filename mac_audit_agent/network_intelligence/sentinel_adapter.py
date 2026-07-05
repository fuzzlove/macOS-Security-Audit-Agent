from __future__ import annotations

from typing import Any

from mac_audit_agent.network_intelligence.models import ListeningPort, NetworkConnection, NetworkFinding, NetworkIntelligenceSnapshot, NetworkPosture


def sentinel_scan_to_snapshot(payload: dict[str, Any]) -> NetworkIntelligenceSnapshot:
    snapshot = NetworkIntelligenceSnapshot(timestamp=str(payload.get("timestamp", "")))
    snapshot.connections = [
        NetworkConnection(
            timestamp=snapshot.timestamp,
            protocol=str(item.get("protocol", "")),
            local_address=str(item.get("local_address", "")),
            local_port=str(item.get("local_port", "")),
            remote_address=str(item.get("remote_address", "")),
            remote_port=str(item.get("remote_port", "")),
            state=str(item.get("state", "")),
            pid=item.get("pid") if isinstance(item.get("pid"), int) else None,
            process_name=str(item.get("process", item.get("process_name", ""))),
            process_path=str(item.get("binary_path", item.get("process_path", ""))),
            user=str(item.get("user", "")),
            source_collector="network_sentinel",
            risk_level=_severity_to_msaa(str(item.get("severity", "info"))),
            evidence=str(item.get("reason", "")),
        )
        for item in payload.get("connections", [])
        if isinstance(item, dict)
    ]
    snapshot.listeners = [
        ListeningPort(
            timestamp=snapshot.timestamp,
            protocol=str(item.get("protocol", "")),
            local_address=str(item.get("local_address", item.get("address", ""))),
            port=str(item.get("port", "")),
            pid=item.get("pid") if isinstance(item.get("pid"), int) else None,
            process_name=str(item.get("process", item.get("process_name", ""))),
            user=str(item.get("user", "")),
            service_guess=str(item.get("service_guess", "")),
            source_collector="network_sentinel",
            risk_level=_severity_to_msaa(str(item.get("severity", "info"))),
            evidence=str(item.get("reason", "")),
        )
        for item in payload.get("listeners", [])
        if isinstance(item, dict)
    ]
    routes = payload.get("routes", {}) if isinstance(payload.get("routes", {}), dict) else {}
    route = routes.get("default_route", {}) if isinstance(routes.get("default_route", {}), dict) else {}
    snapshot.posture = NetworkPosture(
        timestamp=snapshot.timestamp,
        gateway=str(route.get("gateway", "")),
        active_interface=str(route.get("interface", "")),
        dns_servers=[str(item.get("nameserver")) for item in payload.get("dns_entries", []) if isinstance(item, dict) and item.get("nameserver")],
        source_collector="network_sentinel",
    )
    snapshot.findings = [
        NetworkFinding(
            title=str(item.get("title", "")),
            severity=_severity_to_msaa(str(item.get("severity", "info"))),
            confidence="medium",
            evidence=str(item.get("evidence", item.get("reason", ""))),
            suggested_fix=str(item.get("recommendation", "")),
            source="network_sentinel",
        )
        for item in payload.get("findings", [])
        if isinstance(item, dict)
    ]
    snapshot.baseline_comparison = payload.get("baseline_comparison", {}) if isinstance(payload.get("baseline_comparison", {}), dict) else {}
    snapshot.diagnostics = {"adapter": "network_sentinel", "errors": payload.get("errors", []) if isinstance(payload.get("errors", []), list) else []}
    return snapshot


def _severity_to_msaa(value: str) -> str:
    normalized = value.strip().lower()
    return {
        "informational": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }.get(normalized, "info")
