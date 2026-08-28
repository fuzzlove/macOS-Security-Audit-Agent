from __future__ import annotations

from typing import Any

from mac_audit_agent.alerts.action_model import AlertActionRequest, AlertActionResult, AlertActionType
from mac_audit_agent.alerts.action_queue import enqueue_alert_action, mark_action_failed
from mac_audit_agent.alerts.action_trace import record_action_clicked
from mac_audit_agent.evidence.snapshot_service import preserve_evidence_snapshot_for_alert_action
from mac_audit_agent.ui.gui_context import ensure_action_gui_safe
from mac_audit_agent.ui.routes import open_or_queue_timeline_route


def enqueue_and_handle_alert_action(db: Any, request: AlertActionRequest) -> AlertActionResult:
    try:
        enqueue_alert_action(db, request)
        record_action_clicked(db, request)
    except Exception as exc:  # noqa: BLE001
        return AlertActionResult(
            action_id=request.action_id,
            action_type=request.action_type,
            event_id=request.event_id,
            trace_id=request.trace_id,
            status="failed",
            failure_stage="db_write_failed",
            user_message="Action failed: db_write_failed.",
            diagnostic_details={"error": str(exc)},
        )
    if request.action_type == AlertActionType.PRESERVE_EVIDENCE_SNAPSHOT.value:
        return preserve_evidence_snapshot_for_alert_action(db, request)
    if request.action_type == AlertActionType.OPEN_TIMELINE.value:
        safe, reason = ensure_action_gui_safe(request.action_type)
        if not safe:
            request.payload["gui_safety_warning"] = reason
        return open_or_queue_timeline_route(db, request)
    if request.action_type in {AlertActionType.ACKNOWLEDGE.value, AlertActionType.DISMISS.value}:
        if request.action_type == AlertActionType.ACKNOWLEDGE.value and request.event_id:
            db.acknowledge_alert_group(request.event_id)
        result = AlertActionResult(
            action_id=request.action_id,
            action_type=request.action_type,
            event_id=request.event_id,
            trace_id=request.trace_id,
            status="succeeded",
            user_message="Alert acknowledged." if request.action_type == AlertActionType.ACKNOWLEDGE.value else "Alert dismissed.",
        )
        from mac_audit_agent.alerts.action_queue import mark_action_succeeded
        from mac_audit_agent.alerts.action_trace import record_action_result

        mark_action_succeeded(db, result)
        record_action_result(db, result)
        return result
    mark_action_failed(db, request.action_id, f"Unsupported action: {request.action_type}", "unknown")
    return AlertActionResult(
        action_id=request.action_id,
        action_type=request.action_type,
        event_id=request.event_id,
        trace_id=request.trace_id,
        status="unsupported",
        failure_stage="unknown",
        user_message=f"Unsupported alert action: {request.action_type}.",
    )
