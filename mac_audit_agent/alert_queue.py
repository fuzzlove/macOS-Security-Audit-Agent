from __future__ import annotations

import json
import time
from uuid import uuid4
from pathlib import Path
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace, utc_now_iso
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_wake import notify_user_notifier_event_available


def queue_visible_alert_for_notifier(
    db: AuditDatabase,
    event: BackgroundMonitorEvent,
    *,
    force: bool = False,
    reason: str = "queued_for_user_notifier",
    wake: bool = True,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    try:
        metadata = json.loads(event.metadata_json or "{}")
    except json.JSONDecodeError:
        metadata = {}
    metadata.update(
        {
            "test_event": bool(metadata.get("test_event", event.simulated)),
            "force_delivery": bool(force or metadata.get("force_delivery")),
            "bypass_cooldown": bool(force or metadata.get("bypass_cooldown")),
            "bypass_rate_limit": bool(force or metadata.get("bypass_rate_limit")),
            "queue_delay_bypassed": bool(force or metadata.get("queue_delay_bypassed")),
            "requires_visible_render": True,
            "queued_for_user_notifier": True,
            "queued_reason": reason,
        }
    )
    event.metadata_json = json.dumps(metadata, sort_keys=True)
    stored = db.record_monitor_event(event, dedupe_window_seconds=0)
    db.record_event_alert_trace(
        EventAlertTrace(
            trace_id=f"trace-{event.event_id}",
            event_id=event.event_id,
            event_type=event.event_type,
            original_event_type=event.event_type,
            normalized_event_type=event.event_type,
            canonical_event_type=event.event_type,
            severity=event.severity,
            detector_source=event.source,
            created_at=event.timestamp,
            stored_db_path=str(db.path),
            stored_success=bool(stored),
            event_written_to_db=bool(stored),
            event_db_path=str(db.path),
            alert_queue_enqueued=bool(stored),
            alert_required=True,
            cooldown_checked=True,
            cooldown_result="bypassed_by_force" if force else "notifier_policy_pending",
            overlay_dispatch_result="queued_for_user_notifier",
            render_verification_status="queued_not_yet_rendered",
        )
    )
    wake_result = notify_user_notifier_event_available(event.event_id, db_path=str(db.path)) if wake else {}
    db.set_background_monitor_state("last_preview_event_id", event.event_id)
    db.set_background_monitor_state("last_preview_queued_at", utc_now_iso())
    db.set_background_monitor_state("last_preview_wake_json", json.dumps(wake_result, sort_keys=True))
    return {"stored": bool(stored), "event_id": event.event_id, "wake": wake_result}


def wait_for_visible_alert_trace(db: AuditDatabase, event_id: str, *, timeout_seconds: float = 5.0, poll_seconds: float = 0.25) -> dict[str, Any]:
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    last_trace = None
    while time.monotonic() < deadline:
        last_trace = db.get_event_alert_trace(event_id)
        if last_trace is not None:
            payload = last_trace.to_dict()
            if payload.get("render_verification_status") in {"verified_visible", "verified_by_notifier_window_state"} or payload.get("visible_alert_id"):
                return {"visible": True, "trace": payload}
            if str(payload.get("render_verification_status", "")).startswith("failed"):
                return {"visible": False, "trace": payload}
        time.sleep(poll_seconds)
    return {"visible": False, "trace": last_trace.to_dict() if last_trace else {}, "timeout": timeout_seconds}


def build_diagnostic_alert_event(*, event_type: str = "msaa_diagnostic_delivery", severity: str = "critical", source: str = "pre_uat_audit", evidence: str = "MSAA diagnostic delivery event.", run_id: str = "") -> BackgroundMonitorEvent:
    unique = uuid4().hex
    created_at = utc_now_iso()
    event_id = f"diagnostic-{unique}"
    trace_id = f"trace-{event_id}"
    grouping_key = f"diagnostic:{run_id or unique}:{event_id}"
    event = BackgroundMonitorEvent(
        event_id=event_id,
        timestamp=created_at,
        event_type=event_type,
        evidence=evidence,
        severity=severity,
        source=source,
        process_name=source,
        pid=0,
        confidence="high",
        recommendation="Confirm that the bottom-right alert is visible.",
        simulated=True,
        rule_id=event_type,
        rule_name=event_type,
        trigger_rule_id=event_type,
        trigger_rule_name=event_type,
        trigger_source=source,
    )
    event.metadata_json = json.dumps({
        "diagnostic_event": True,
        "test_event": True,
        "run_id": run_id,
        "trace_id": trace_id,
        "grouping_key": grouping_key,
        "bypass_cooldown": True,
        "bypass_rate_limit": True,
        "requires_visible_render": True,
        "created_at": created_at,
    }, sort_keys=True)
    event.duplicate_group_key = grouping_key
    return event


__all__ = ["build_diagnostic_alert_event", "queue_visible_alert_for_notifier", "wait_for_visible_alert_trace"]
