from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from mac_audit_agent.alerts.action_model import AlertActionRequest, AlertActionResult
from mac_audit_agent.models import utc_now_iso


def ensure_alert_action_schema(db: Any) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS alert_action_requests (
            action_id TEXT PRIMARY KEY,
            action_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            source_component TEXT NOT NULL,
            event_id TEXT NOT NULL DEFAULT '',
            trace_id TEXT NOT NULL DEFAULT '',
            finding_id TEXT NOT NULL DEFAULT '',
            scan_id TEXT NOT NULL DEFAULT '',
            assessment_id TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            source_db_path TEXT NOT NULL DEFAULT '',
            timeline_focus_time TEXT NOT NULL DEFAULT '',
            requested_by_user INTEGER NOT NULL DEFAULT 1,
            requires_main_gui INTEGER NOT NULL DEFAULT 0,
            can_run_headless INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            error TEXT NOT NULL DEFAULT '',
            result_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alert_action_results (
            action_id TEXT PRIMARY KEY,
            action_type TEXT NOT NULL,
            event_id TEXT NOT NULL DEFAULT '',
            trace_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            artifact_paths_json TEXT NOT NULL DEFAULT '[]',
            opened_route_json TEXT NOT NULL DEFAULT '{}',
            failure_stage TEXT NOT NULL DEFAULT '',
            user_message TEXT NOT NULL DEFAULT '',
            diagnostic_details_json TEXT NOT NULL DEFAULT '{}'
        );
        """
    )
    db.conn.commit()


def enqueue_alert_action(db: Any, request: AlertActionRequest) -> AlertActionRequest:
    ensure_alert_action_schema(db)
    db.conn.execute(
        """
        INSERT OR REPLACE INTO alert_action_requests
        (action_id, action_type, created_at, source_component, event_id, trace_id, finding_id, scan_id,
         assessment_id, severity, category, title, summary, source_db_path, timeline_focus_time,
         requested_by_user, requires_main_gui, can_run_headless, payload_json, status, error, result_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.action_id,
            request.action_type,
            request.created_at,
            request.source_component,
            request.event_id,
            request.trace_id,
            request.finding_id,
            request.scan_id,
            request.assessment_id,
            request.severity,
            request.category,
            request.title,
            request.summary,
            request.source_db_path,
            request.timeline_focus_time,
            int(bool(request.requested_by_user)),
            int(bool(request.requires_main_gui)),
            int(bool(request.can_run_headless)),
            json.dumps(request.payload, sort_keys=True),
            request.status,
            request.error,
            json.dumps(request.result, sort_keys=True),
            utc_now_iso(),
        ),
    )
    db.conn.commit()
    return request


def _request_from_row(row: Any) -> AlertActionRequest:
    def _json_dict(value: str) -> dict[str, Any]:
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    return AlertActionRequest(
        action_id=str(row["action_id"]),
        action_type=str(row["action_type"]),
        created_at=str(row["created_at"]),
        source_component=str(row["source_component"]),
        event_id=str(row["event_id"] or ""),
        trace_id=str(row["trace_id"] or ""),
        finding_id=str(row["finding_id"] or ""),
        scan_id=str(row["scan_id"] or ""),
        assessment_id=str(row["assessment_id"] or ""),
        severity=str(row["severity"] or ""),
        category=str(row["category"] or ""),
        title=str(row["title"] or ""),
        summary=str(row["summary"] or ""),
        source_db_path=str(row["source_db_path"] or ""),
        timeline_focus_time=str(row["timeline_focus_time"] or ""),
        requested_by_user=bool(row["requested_by_user"]),
        requires_main_gui=bool(row["requires_main_gui"]),
        can_run_headless=bool(row["can_run_headless"]),
        payload=_json_dict(str(row["payload_json"] or "{}")),
        status=str(row["status"] or "pending"),
        error=str(row["error"] or ""),
        result=_json_dict(str(row["result_json"] or "{}")),
    )


def get_pending_actions(db: Any) -> list[AlertActionRequest]:
    ensure_alert_action_schema(db)
    rows = db.conn.execute(
        "SELECT * FROM alert_action_requests WHERE status IN ('pending', 'queued_for_main_gui') ORDER BY created_at ASC"
    ).fetchall()
    return [_request_from_row(row) for row in rows]


def get_action(db: Any, action_id: str) -> AlertActionRequest | None:
    ensure_alert_action_schema(db)
    row = db.conn.execute("SELECT * FROM alert_action_requests WHERE action_id = ?", (action_id,)).fetchone()
    return _request_from_row(row) if row else None


def _mark(db: Any, action_id: str, status: str, *, error: str = "", result: dict[str, Any] | None = None) -> None:
    ensure_alert_action_schema(db)
    db.conn.execute(
        "UPDATE alert_action_requests SET status = ?, error = ?, result_json = ?, updated_at = ? WHERE action_id = ?",
        (status, error, json.dumps(result or {}, sort_keys=True), utc_now_iso(), action_id),
    )
    db.conn.commit()


def mark_action_running(db: Any, action_id: str) -> None:
    _mark(db, action_id, "running")


def mark_action_succeeded(db: Any, result: AlertActionResult) -> None:
    ensure_alert_action_schema(db)
    _mark(db, result.action_id, result.status, result=result.to_dict())
    db.conn.execute(
        """
        INSERT OR REPLACE INTO alert_action_results
        (action_id, action_type, event_id, trace_id, status, started_at, completed_at, artifact_paths_json,
         opened_route_json, failure_stage, user_message, diagnostic_details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.action_id,
            result.action_type,
            result.event_id,
            result.trace_id,
            result.status,
            result.started_at,
            result.completed_at,
            json.dumps(result.artifact_paths, sort_keys=True),
            json.dumps(result.opened_route or {}, sort_keys=True),
            result.failure_stage,
            result.user_message,
            json.dumps(result.diagnostic_details, sort_keys=True),
        ),
    )
    db.conn.commit()


def mark_action_failed(db: Any, action_id: str, error: str, failure_stage: str) -> None:
    request = get_action(db, action_id)
    result = AlertActionResult(
        action_id=action_id,
        action_type=request.action_type if request else "",
        event_id=request.event_id if request else "",
        trace_id=request.trace_id if request else "",
        status="failed",
        failure_stage=failure_stage,
        user_message=f"Action failed: {failure_stage}.",
        diagnostic_details={"error": error},
    )
    mark_action_succeeded(db, result)


def get_latest_action_for_event(db: Any, event_id: str, action_type: str) -> AlertActionRequest | None:
    ensure_alert_action_schema(db)
    row = db.conn.execute(
        "SELECT * FROM alert_action_requests WHERE event_id = ? AND action_type = ? ORDER BY created_at DESC LIMIT 1",
        (event_id, action_type),
    ).fetchone()
    return _request_from_row(row) if row else None


def cleanup_completed_actions(db: Any, retention_days: int = 30) -> None:
    ensure_alert_action_schema(db)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    db.conn.execute(
        "DELETE FROM alert_action_requests WHERE status IN ('succeeded', 'failed', 'unsupported') AND updated_at < ?",
        (cutoff,),
    )
    db.conn.execute("DELETE FROM alert_action_results WHERE completed_at < ?", (cutoff,))
    db.conn.commit()
