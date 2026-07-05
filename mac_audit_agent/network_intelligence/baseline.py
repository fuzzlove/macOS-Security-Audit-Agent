from __future__ import annotations

from mac_audit_agent.network_intelligence.models import ListeningPort, NetworkConnection, NetworkIntelligenceSnapshot, NetworkPosture


def compare_network_baseline(current: NetworkIntelligenceSnapshot, baseline: NetworkIntelligenceSnapshot | None) -> dict[str, object]:
    if baseline is None:
        for item in current.connections:
            item.baseline_status = "unknown"
        for item in current.listeners:
            item.baseline_status = "unknown"
        return {
            "status": "no_baseline",
            "new_connections": [],
            "removed_connections": [],
            "new_listeners": [],
            "removed_listeners": [],
            "posture_changes": [],
        }

    baseline_connections = {item.key(): item for item in baseline.connections}
    current_connections = {item.key(): item for item in current.connections}
    baseline_listeners = {item.key(): item for item in baseline.listeners}
    current_listeners = {item.key(): item for item in current.listeners}

    new_connections: list[dict[str, object]] = []
    for key, item in current_connections.items():
        item.baseline_status = "known" if key in baseline_connections else "new"
        if item.baseline_status == "new":
            new_connections.append(item.to_dict())

    new_listeners: list[dict[str, object]] = []
    for key, item in current_listeners.items():
        item.baseline_status = "known" if key in baseline_listeners else "new"
        if item.baseline_status == "new":
            new_listeners.append(item.to_dict())

    posture_changes = compare_posture(current.posture, baseline.posture)
    return {
        "status": "drift" if new_connections or new_listeners or posture_changes else "match",
        "new_connections": new_connections,
        "removed_connections": [item.to_dict() for key, item in baseline_connections.items() if key not in current_connections],
        "new_listeners": new_listeners,
        "removed_listeners": [item.to_dict() for key, item in baseline_listeners.items() if key not in current_listeners],
        "posture_changes": posture_changes,
    }


def compare_posture(current: NetworkPosture, baseline: NetworkPosture) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for field_name in ["gateway", "vpn_active", "vpn_name", "proxy_enabled", "proxy_details", "active_interface", "local_ip", "subnet"]:
        before = getattr(baseline, field_name)
        after = getattr(current, field_name)
        if before != after:
            changes.append({"field": field_name, "previous": str(before), "current": str(after)})
    if baseline.dns_servers != current.dns_servers:
        changes.append({"field": "dns_servers", "previous": ", ".join(baseline.dns_servers), "current": ", ".join(current.dns_servers)})
    return changes


def snapshot_from_dict(payload: dict[str, object]) -> NetworkIntelligenceSnapshot:
    posture_payload = payload.get("posture", {}) if isinstance(payload.get("posture", {}), dict) else {}
    snapshot = NetworkIntelligenceSnapshot(
        snapshot_id=str(payload.get("snapshot_id", "")) or "baseline",
        timestamp=str(payload.get("timestamp", "")),
        posture=NetworkPosture(**{key: value for key, value in posture_payload.items() if key in NetworkPosture.__dataclass_fields__}),
    )
    snapshot.connections = [
        NetworkConnection(**{key: value for key, value in item.items() if key in NetworkConnection.__dataclass_fields__})
        for item in payload.get("connections", [])
        if isinstance(item, dict)
    ]
    snapshot.listeners = [
        ListeningPort(**{key: value for key, value in item.items() if key in ListeningPort.__dataclass_fields__})
        for item in payload.get("listeners", [])
        if isinstance(item, dict)
    ]
    return snapshot
