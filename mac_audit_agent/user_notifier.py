from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

from mac_audit_agent.launch_agent import MAC_AUDIT_AGENT_ENV_DB_PATH, MONITOR_ROLE_USER, default_monitor_db_path
from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace, utc_now_iso
from mac_audit_agent.monitor import BackgroundMonitorService
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import MAC_AUDIT_AGENT_ALERT_TRACE_PATH, MAC_AUDIT_AGENT_SETTINGS_PATH
from mac_audit_agent.version import APP_VERSION, current_git_commit


def _secure_receipt_files(receipt: Path) -> None:
    for candidate in (receipt, Path(f"{receipt}-wal"), Path(f"{receipt}-shm")):
        try:
            if candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_uid == os.getuid():
                candidate.chmod(0o600)
        except OSError:
            continue


def _readonly_events(source: Path, limit: int = 200) -> list[BackgroundMonitorEvent]:
    uri = "file:{}?mode=ro".format(source.resolve(strict=False).as_posix())
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        # Source notification_sent is not a delivery receipt. Older daemons and
        # diagnostic publishers may set it outside a GUI session. Receipt-store
        # event IDs are the authoritative per-user dedupe boundary. A bounded
        # newest window prevents historical backlog from starving live alerts.
        rows = connection.execute(
            "SELECT * FROM background_monitor_events ORDER BY timestamp DESC, event_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        rows.reverse()
    fields = BackgroundMonitorEvent.__dataclass_fields__
    events: list[BackgroundMonitorEvent] = []
    for row in rows:
        payload = {key: row[key] for key in row.keys() if key in fields}
        # Rich detector identity (rule ID, trigger source, related path, etc.)
        # is stored in provenance_json rather than dedicated event columns.
        # Dropping it at the trust boundary caused valid critical alerts to be
        # rejected by the notifier as incomplete/missing_rule_id.
        try:
            provenance = json.loads(str(row["provenance_json"] or "{}")) if "provenance_json" in row.keys() else {}
        except json.JSONDecodeError:
            provenance = {}
        if isinstance(provenance, dict):
            payload.update({key: value for key, value in provenance.items() if key in fields and key not in payload})
        events.append(BackgroundMonitorEvent(**payload))
    return events


def poll_once(source: Path, receipt: Path) -> list[BackgroundMonitorEvent]:
    receipt_db = AuditDatabase(receipt)
    service = BackgroundMonitorService(receipt, mode=MONITOR_ROLE_USER, record_startup=False)
    copied: list[BackgroundMonitorEvent] = []
    cursor_before = receipt_db.get_background_monitor_state("last_event_consumed", "")
    for event in _readonly_events(source):
        existing = receipt_db.conn.execute("SELECT notification_sent FROM background_monitor_events WHERE event_id = ?", (event.event_id,)).fetchone()
        if existing:
            continue
        receipt_event = replace(
            event,
            notification_sent=False,
            notification_error="",
            notification_returncode=None,
            notification_decision="log_only",
            notification_reason="awaiting_user_notifier_policy",
            popup_allowed=False,
            visible_alert_shown=False,
            cooldown_suppressed=False,
            last_suppression_reason="",
        )
        receipt_db.record_background_monitor_event(receipt_event, dedupe_window_seconds=0)
        receipt_db.record_event_alert_trace(
            EventAlertTrace(
                trace_id=f"trace-{event.event_id}",
                event_id=event.event_id,
                event_type=str(event.event_type),
                created_at=event.timestamp,
                stored_db_path=str(source),
                stored_success=True,
                notifier_db_path=str(source),
                notifier_poll_seen=True,
                notifier_poll_time=utc_now_iso(),
                notifier_cursor_before=cursor_before,
                notifier_cursor_after=event.event_id,
                notifier_seen=True,
                notifier_received=True,
                notifier_seen_at=utc_now_iso(),
                notifier_settings_version=str(getattr(service.monitor_settings, "settings_version", "")),
                notification_policy_checked=False,
                notification_policy_result="pending_notifier_policy",
                alert_queue_enqueued=True,
                render_verification_status="received_render_pending",
            )
        )
        copied.append(event)
    receipt_db.set_background_monitor_state("notifier_event_source", str(source))
    receipt_db.set_background_monitor_state("notifier_receipt_database", str(receipt))
    receipt_db.set_background_monitor_state("notifier_transport", "readonly_sqlite_event_source+per_user_receipt_store")
    receipt_db.set_background_monitor_state("notifier_executable", str(Path(__import__("sys").executable).resolve(strict=False)))
    receipt_db.set_background_monitor_state("notifier_build_id", current_git_commit())
    receipt_db.set_background_monitor_state("notifier_application_version", APP_VERSION)
    receipt_db.set_background_monitor_state("notifier_last_error", "")
    receipt_db.set_background_monitor_state("notification_pipeline_broken", "0")
    _secure_receipt_files(receipt)
    receipt_db.close()
    service.process_pending_notifications()
    return copied


def _record_poll_failure(receipt: Path, exc: BaseException) -> None:
    """Record a sanitized health failure without copying database content."""
    try:
        db = AuditDatabase(receipt)
        category = "database_malformed" if "malformed" in str(exc).lower() else "database_unreadable"
        db.set_background_monitor_state("notifier_running", "1")
        db.set_background_monitor_state("notifier_last_poll", utc_now_iso())
        db.set_background_monitor_state("notifier_last_error", f"{category}:{type(exc).__name__}")
        db.set_background_monitor_state("notification_pipeline_broken", "1")
        db.close()
        _secure_receipt_files(receipt)
    except (OSError, sqlite3.Error):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msaa-user-notifier")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=int, default=5)
    args = parser.parse_args(argv)
    source = Path(os.environ.get(MAC_AUDIT_AGENT_ENV_DB_PATH, "") or default_monitor_db_path("user")).expanduser()
    receipt = Path(
        os.environ.get(MAC_AUDIT_AGENT_ALERT_TRACE_PATH, "")
        or os.environ.get(MAC_AUDIT_AGENT_SETTINGS_PATH, "")
        or default_monitor_db_path("user")
    ).expanduser()
    if args.once or not args.run:
        try:
            poll_once(source, receipt)
            return 0
        except (OSError, sqlite3.Error) as exc:
            _record_poll_failure(receipt, exc)
            return 2
    failures = 0
    while True:
        try:
            poll_once(source, receipt)
            failures = 0
        except (OSError, sqlite3.Error) as exc:
            failures = min(failures + 1, 6)
            _record_poll_failure(receipt, exc)
        time.sleep(max(1, min(60, args.poll_interval)) * max(1, min(8, 2**failures)))


if __name__ == "__main__":
    raise SystemExit(main())
