from pathlib import Path

from mac_audit_agent.alert_queue import build_diagnostic_alert_event, queue_visible_alert_for_notifier
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier import poll_once


def test_diagnostic_events_have_unique_non_groupable_identity(tmp_path: Path) -> None:
    first = build_diagnostic_alert_event(run_id="run-1")
    second = build_diagnostic_alert_event(run_id="run-1")
    assert first.event_id != second.event_id
    assert first.duplicate_group_key != second.duplicate_group_key
    assert '"bypass_cooldown": true' in first.metadata_json


def test_diagnostic_event_is_persisted_and_published_without_cooldown(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "events.sqlite3")
    event = build_diagnostic_alert_event(run_id="run-2")
    result = queue_visible_alert_for_notifier(db, event, force=True, wake=False)
    trace = db.get_event_alert_trace(event.event_id)
    assert result["stored"] is True
    assert trace is not None
    payload = trace.to_dict()
    assert payload["event_written_to_db"] is True
    assert payload["alert_queue_enqueued"] is True
    assert payload["cooldown_result"] == "bypassed_by_force"


def test_notifier_receipt_dedupe_does_not_trust_source_notification_sent(tmp_path: Path, monkeypatch) -> None:
    source_path = tmp_path / "system.sqlite3"
    receipt_path = tmp_path / "receipts.sqlite3"
    source = AuditDatabase(source_path)
    event = build_diagnostic_alert_event(run_id="legacy-daemon")
    assert source.record_background_monitor_event(event, dedupe_window_seconds=0)
    source.update_monitor_event_notification(
        event.event_id,
        notification_sent=True,
        notification_error="",
        notification_returncode=0,
        notification_decision="skipped_non_interactive",
        notification_reason="legacy_system_daemon",
        cooldown_remaining_seconds=0,
        popup_allowed=False,
        visible_alert_shown=False,
        alert_style="critical_red",
        cooldown_suppressed=False,
        last_suppression_reason="",
    )
    source.close()
    monkeypatch.setattr(
        "mac_audit_agent.monitor.BackgroundMonitorService.process_pending_notifications",
        lambda self, limit=200: [],
    )

    copied = poll_once(source_path, receipt_path)
    assert [item.event_id for item in copied] == [event.event_id]
    assert copied[0].rule_id == event.rule_id
    assert copied[0].trigger_rule_id == event.trigger_rule_id
    receipt = AuditDatabase(receipt_path)
    trace = receipt.get_event_alert_trace(event.event_id)
    assert trace is not None
    assert trace.to_dict()["notifier_received"] is True
    stored = receipt.recent_background_monitor_events(limit=1)[0]
    assert stored.notification_sent is False
    assert stored.notification_reason == "awaiting_user_notifier_policy"
    receipt.close()
