from __future__ import annotations

import json
import socket

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.persistence_intelligence.baseline import PersistenceBaselineManager
from mac_audit_agent.persistence_intelligence.models import PersistenceItem


EVENT_BY_MECHANISM = {
    "launch_agent": "launchagent_added",
    "launch_daemon": "launchdaemon_added",
    "native_messaging_host": "browser_native_messaging_host_added",
    "privileged_helper": "privileged_helper_added",
    "ssh_authorized_key": "ssh_authorized_key_added",
    "cron": "scheduled_task_added",
    "shell_startup": "shell_profile_modified",
    "applescript_persistence": "applescript_persistence_added",
}

REMOVED_EVENT_BY_MECHANISM = {
    "launch_agent": "launchagent_removed",
    "launch_daemon": "launchdaemon_removed",
}


def events_from_baseline_changes(changes: dict, items: list[PersistenceItem]) -> list[BackgroundMonitorEvent]:
    by_id = {item.item_id: item for item in items}
    events: list[BackgroundMonitorEvent] = []
    def _event(item: PersistenceItem, event_type: str, evidence: str, severity: str | None = None) -> BackgroundMonitorEvent:
        resolved_severity = severity or ("critical" if item.risk_level == "CRITICAL" else "high" if item.risk_level == "HIGH" else "medium")
        cvss_score = round(min(10.0, max(0.0, item.risk_score / 10.0)), 1)
        if event_type == "ssh_authorized_key_added":
            resolved_severity = "critical"
            cvss_score = max(9.0, cvss_score)
        metadata = {
            "hostname": socket.gethostname(),
            "username": item.responsible_user or item.owner,
            "event_category": "persistence",
            "persistence_type": item.mechanism,
            "object_path": item.path,
            "process_name": item.responsible_process,
            "parent_process": item.parent_process,
            "signature_status": item.signed_status,
            "developer_identity": item.developer_identity,
            "team_id": item.team_id,
            "sha256": item.target_hash_sha256,
            "mitre_attack_mapping": item.mitre_techniques,
            "severity": resolved_severity,
            "cvss_score": cvss_score,
            "description": evidence,
            "recommended_action": item.recommended_verification,
            "analyst_status": item.analyst_status,
        }
        return BackgroundMonitorEvent(
            event_id=f"persistence-{item.item_id}-{utc_now_iso()}",
            timestamp=utc_now_iso(),
            event_type=event_type,
            severity=resolved_severity,
            source="persistence_intelligence_watch",
            evidence=evidence,
            confidence=item.confidence,
            recommendation=item.recommended_verification,
            metadata_json=json.dumps(metadata, sort_keys=True),
            related_process=item.responsible_process,
            related_path=item.path,
            related_user=item.responsible_user,
            related_file_hash=item.target_hash_sha256,
        )

    for item_payload in changes.get("added", []) or []:
        item = by_id.get(item_payload.get("item_id", "")) if isinstance(item_payload, dict) else None
        if item is None:
            continue
        event_type = EVENT_BY_MECHANISM.get(item.mechanism, "persistence_item_modified")
        events.append(_event(item, event_type, f"Persistence item added: {item.label or item.path}"))
    for item_payload in changes.get("removed", []) or []:
        if not isinstance(item_payload, dict):
            continue
        item = PersistenceItem.create(str(item_payload.get("mechanism", "persistence_item")), str(item_payload.get("path", "")), label=str(item_payload.get("label", "")))
        item.item_id = str(item_payload.get("item_id", item.item_id))
        event_type = REMOVED_EVENT_BY_MECHANISM.get(item.mechanism, "persistence_item_modified")
        events.append(_event(item, event_type, f"Persistence item removed: {item.label or item.path}", "medium"))
    for key, event_type in [
        ("modified", "persistence_item_modified"),
        ("hash_changed", "persistence_target_hash_changed"),
        ("permission_changed", "persistence_item_modified"),
        ("owner_changed", "persistence_item_modified"),
        ("loaded_state_changed", "persistence_item_modified"),
        ("disabled_state_changed", "persistence_item_modified"),
    ]:
        for payload in changes.get(key, []) or []:
            item_payload = payload.get("after", payload) if isinstance(payload, dict) else {}
            item = by_id.get(item_payload.get("item_id", "")) if isinstance(item_payload, dict) else None
            if item is None:
                continue
            events.append(_event(item, event_type, f"Persistence item {key.replace('_', ' ')}: {item.label or item.path}"))
    return events


def compare_for_watch(baseline_name: str, items: list[PersistenceItem], baseline_dir=None) -> dict:
    return PersistenceBaselineManager(baseline_dir).compare_baseline(baseline_name, items)
