from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.alerts.action_model import AlertActionRequest, AlertActionResult
from mac_audit_agent.alerts.action_queue import mark_action_succeeded
from mac_audit_agent.alerts.action_trace import record_action_result
from mac_audit_agent.models import utc_now_iso


@dataclass
class Route:
    view: str
    params: dict[str, Any]
    route_id: str = field(default_factory=lambda: f"route-{uuid4()}")
    created_at: str = field(default_factory=utc_now_iso)
    source_action_id: str = ""
    status: str = "pending"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Route":
        return cls(**{key: value for key, value in dict(payload).items() if key in cls.__dataclass_fields__})


def build_timeline_route_from_alert_action(request: AlertActionRequest) -> Route:
    if not request.event_id and not request.timeline_focus_time:
        raise ValueError("Open Timeline requires event_id or focus_time.")
    return Route(
        view="timeline",
        source_action_id=request.action_id,
        params={
            "event_id": request.event_id,
            "trace_id": request.trace_id,
            "finding_id": request.finding_id,
            "focus_time": request.timeline_focus_time,
            "category": request.category,
            "severity": request.severity,
            "source_db_path": request.source_db_path,
            "time_window_before_seconds": 300,
            "time_window_after_seconds": 300,
        },
    )


def open_or_queue_timeline_route(db: Any, request: AlertActionRequest) -> AlertActionResult:
    from mac_audit_agent.ui.pending_routes import enqueue_pending_route

    started = utc_now_iso()
    try:
        route = build_timeline_route_from_alert_action(request)
        enqueue_pending_route(db, route)
        result = AlertActionResult(
            action_id=request.action_id,
            action_type=request.action_type,
            event_id=request.event_id,
            trace_id=request.trace_id,
            status="queued_for_main_gui",
            started_at=started,
            opened_route=route.to_dict(),
            failure_stage="pending_route_saved",
            user_message="Timeline queued. Open MSAA to view it.",
        )
        mark_action_succeeded(db, result)
        record_action_result(db, result)
        return result
    except Exception as exc:  # noqa: BLE001
        result = AlertActionResult(
            action_id=request.action_id,
            action_type=request.action_type,
            event_id=request.event_id,
            trace_id=request.trace_id,
            status="failed",
            started_at=started,
            failure_stage="route_failed",
            user_message="Open Timeline failed: route_failed.",
            diagnostic_details={"error": str(exc)},
        )
        mark_action_succeeded(db, result)
        record_action_result(db, result, error=str(exc))
        return result
