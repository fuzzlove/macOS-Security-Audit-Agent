from __future__ import annotations

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.persistence_intelligence.baseline import PersistenceBaselineManager
from mac_audit_agent.persistence_intelligence.models import PersistenceItem


EVENT_BY_MECHANISM = {
    "launch_agent": "launchagent_added",
    "launch_daemon": "launchdaemon_added",
    "native_messaging_host": "browser_native_messaging_host_added",
    "privileged_helper": "privileged_helper_added",
}

REMOVED_EVENT_BY_MECHANISM = {
    "launch_agent": "launchagent_removed",
    "launch_daemon": "launchdaemon_removed",
}


def events_from_baseline_changes(changes: dict, items: list[PersistenceItem]) -> list[BackgroundMonitorEvent]:
    by_id = {item.item_id: item for item in items}
    events: list[BackgroundMonitorEvent] = []
    def _event(item: PersistenceItem, event_type: str, evidence: str, severity: str | None = None) -> BackgroundMonitorEvent:
        return BackgroundMonitorEvent(
            event_id=f"persistence-{item.item_id}-{utc_now_iso()}",
            timestamp=utc_now_iso(),
            event_type=event_type,
            severity=severity or ("high" if item.risk_level in {"HIGH", "CRITICAL"} else "medium"),
            source="persistence_intelligence_watch",
            evidence=evidence,
            confidence=item.confidence,
            metadata_json="{}",
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
