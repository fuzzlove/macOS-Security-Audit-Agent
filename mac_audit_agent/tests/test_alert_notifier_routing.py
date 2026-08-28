from __future__ import annotations

from pathlib import Path

from mac_audit_agent.alert_queue import build_diagnostic_alert_event, queue_visible_alert_for_notifier
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.gui_context import detect_gui_execution_context


def test_cli_context_cannot_render_overlay(monkeypatch) -> None:
    monkeypatch.delenv("MAC_AUDIT_AGENT_MONITOR_ROLE", raising=False)
    context = detect_gui_execution_context(role="")
    assert context.can_render_overlay is False
    assert context.is_cli_process is True


def test_notification_manager_blocks_overlay_launch_outside_notifier(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db, role="")
    assert manager._ensure_security_overlay_process() is False
    assert db.get_background_monitor_state("last_alert_failure_stage") == "failed_qt_context"
    assert db.get_background_monitor_state("last_overlay_error") == "overlay_render_disallowed_in_current_context"


def test_preview_queue_records_trace_without_direct_render(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    event = build_diagnostic_alert_event(event_type="alert_preview_high", severity="high", source="test", evidence="preview")
    result = queue_visible_alert_for_notifier(db, event, force=True, wake=False)
    trace = db.get_event_alert_trace(event.event_id)
    assert result["stored"] is True
    assert trace is not None
    payload = trace.to_dict()
    assert payload["overlay_dispatch_result"] == "queued_for_user_notifier"
    assert payload["render_verification_status"] == "queued_not_yet_rendered"
    assert payload["visible_alert_id"] == ""
