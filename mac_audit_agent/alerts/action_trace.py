from __future__ import annotations

import json
from typing import Any

from mac_audit_agent.alerts.action_model import AlertActionRequest, AlertActionResult
from mac_audit_agent.alerts.action_queue import ensure_alert_action_schema
from mac_audit_agent.models import utc_now_iso

FAILURE_STAGES = {
    "missing_event_id",
    "missing_trace_id",
    "event_not_found",
    "trace_not_found",
    "db_write_failed",
    "queue_failed",
    "snapshot_failed",
    "manifest_failed",
    "route_failed",
    "main_gui_not_running",
    "pending_route_saved",
    "unsafe_gui_context",
    "unsupported_python_gui_runtime",
    "timeline_event_missing",
    "permission_denied",
    "unknown",
}


def ensure_action_trace_schema(db: Any) -> None:
    ensure_alert_action_schema(db)
    db.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_action_traces (
            action_id TEXT PRIMARY KEY,
            action_type TEXT NOT NULL,
            event_id TEXT NOT NULL DEFAULT '',
            trace_id TEXT NOT NULL DEFAULT '',
            clicked_at TEXT NOT NULL DEFAULT '',
            enqueued_at TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            source_component TEXT NOT NULL DEFAULT '',
            handled_by TEXT NOT NULL DEFAULT '',
            requires_main_gui INTEGER NOT NULL DEFAULT 0,
            can_run_headless INTEGER NOT NULL DEFAULT 0,
            artifact_paths_json TEXT NOT NULL DEFAULT '[]',
            opened_route_json TEXT NOT NULL DEFAULT '{}',
            failure_stage TEXT NOT NULL DEFAULT '',
            error TEXT NOT NULL DEFAULT '',
            user_message TEXT NOT NULL DEFAULT ''
        )
        """
    )
    db.conn.commit()


def record_action_clicked(db: Any, request: AlertActionRequest) -> None:
    ensure_action_trace_schema(db)
    now = utc_now_iso()
    db.conn.execute(
        """
        INSERT OR REPLACE INTO alert_action_traces
        (action_id, action_type, event_id, trace_id, clicked_at, enqueued_at, status, source_component,
         requires_main_gui, can_run_headless, user_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.action_id,
            request.action_type,
            request.event_id,
            request.trace_id,
            now,
            now,
            request.status,
            request.source_component,
            int(bool(request.requires_main_gui)),
            int(bool(request.can_run_headless)),
            "",
        ),
    )
    db.conn.commit()


def record_action_started(db: Any, request: AlertActionRequest, *, handled_by: str) -> None:
    ensure_action_trace_schema(db)
    db.conn.execute(
        "UPDATE alert_action_traces SET started_at = ?, status = ?, handled_by = ? WHERE action_id = ?",
        (utc_now_iso(), "running", handled_by, request.action_id),
    )
    db.conn.commit()


def record_action_result(db: Any, result: AlertActionResult, *, error: str = "") -> None:
    ensure_action_trace_schema(db)
    db.conn.execute(
        """
        UPDATE alert_action_traces
        SET completed_at = ?, status = ?, artifact_paths_json = ?, opened_route_json = ?,
            failure_stage = ?, error = ?, user_message = ?
        WHERE action_id = ?
        """,
        (
            result.completed_at,
            result.status,
            json.dumps(result.artifact_paths, sort_keys=True),
            json.dumps(result.opened_route or {}, sort_keys=True),
            result.failure_stage,
            error or str(result.diagnostic_details.get("error", "")),
            result.user_message,
            result.action_id,
        ),
    )
    db.conn.commit()
