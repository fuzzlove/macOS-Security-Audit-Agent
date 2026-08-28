from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.alerts.action_handler import enqueue_and_handle_alert_action
from mac_audit_agent.alerts.action_model import AlertActionType, request_from_alert_payload
from mac_audit_agent.intrusion_correlation import IntrusionCorrelationEngine
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


def _event(event_id: str = "event-1") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id=event_id,
        timestamp="2026-07-09T18:00:00+00:00",
        event_type="protected_monitor_tamper_detected",
        severity="critical",
        source="test",
        process_name="launchd",
        evidence="Protected monitor state changed.",
        confidence="high",
    )


def test_preserve_evidence_snapshot_resolves_visible_alert_id(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event(), dedupe_window_seconds=0)
    db.record_event_alert_trace(
        {
            "trace_id": "trace-1",
            "event_id": "event-1",
            "event_type": "protected_monitor_tamper_detected",
            "created_at": utc_now_iso(),
            "stored_success": True,
            "visible_alert_id": "visible-alert-1",
        }
    )
    from mac_audit_agent.evidence import snapshot_service

    monkeypatch.setattr(snapshot_service, "SNAPSHOT_DIR", tmp_path / "snapshots")
    request = request_from_alert_payload(
        {"visible_alert_id": "visible-alert-1", "severity": "critical", "event_type": "protected_monitor_tamper_detected"},
        AlertActionType.PRESERVE_EVIDENCE_SNAPSHOT.value,
        source_component="test_overlay",
    )

    result = enqueue_and_handle_alert_action(db, request)

    assert result.status == "succeeded"
    assert result.event_id == "event-1"
    assert result.trace_id == "trace-1"
    assert result.artifact_paths
    assert Path(result.artifact_paths[0]).exists()


def test_monitor_events_read_with_derived_correlation_id(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event(), dedupe_window_seconds=0)

    stored = db.latest_monitor_events(limit=1)[0]

    assert stored.correlation_id.startswith("corr-")


def test_acknowledged_evidenced_alert_logs_duplicate_without_realerting(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("event-1"), dedupe_window_seconds=0)
    request = request_from_alert_payload(
        {"event_id": "event-1", "severity": "critical", "event_type": "protected_monitor_tamper_detected"},
        AlertActionType.ACKNOWLEDGE.value,
        source_component="test_overlay",
    )

    result = enqueue_and_handle_alert_action(db, request)
    duplicate = _event("event-2")
    duplicate.timestamp = "2026-07-09T18:01:00+00:00"
    assert db.record_background_monitor_event(duplicate, dedupe_window_seconds=0) is True

    stored = db.recent_background_monitor_events(limit=2)
    assert result.status == "succeeded"
    assert len(stored) == 2
    assert stored[0].event_id == "event-2"
    assert stored[0].notification_sent is True
    assert stored[0].notification_decision == "acknowledged_duplicate_log_only"
    assert db.pending_background_monitor_events(limit=10) == []


def test_pending_alerts_are_fifo_across_all_severities(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    severities = [("event-info", "info"), ("event-medium", "medium"), ("event-high", "high"), ("event-critical", "critical")]
    for offset, (event_id, severity) in enumerate(severities):
        event = _event(event_id)
        event.timestamp = f"2026-07-09T18:00:0{offset}+00:00"
        event.severity = severity
        event.evidence = f"Evidence {event_id}"
        db.record_background_monitor_event(event, dedupe_window_seconds=0)

    assert [item.event_id for item in db.pending_background_monitor_events(limit=10)] == [item[0] for item in severities]


def test_duplicate_storm_aggregates_while_original_alert_is_pending(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("pending-original"), dedupe_window_seconds=0)
    duplicate = _event("pending-duplicate")
    duplicate.timestamp = "2026-07-10T18:00:00+00:00"

    assert db.record_background_monitor_event(duplicate, dedupe_window_seconds=0) is False

    stored = db.latest_monitor_events(limit=10)
    assert len(stored) == 1
    assert stored[0].occurrence_count == 2
    assert stored[0].duplicate_count == 1


def test_capacity_pruning_preserves_pending_events(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    for offset in range(6):
        event = _event(f"event-{offset}")
        event.timestamp = f"2026-07-09T18:00:0{offset}+00:00"
        event.evidence = f"Evidence {offset}"
        event.notification_sent = offset < 4
        db.record_background_monitor_event(event, dedupe_window_seconds=0)

    removed = db._prune_monitor_event_capacity_if_needed(maximum_rows=5, target_rows=4)

    assert removed == 2
    assert [item.event_id for item in db.pending_background_monitor_events(limit=10)] == ["event-4", "event-5"]
    assert db.conn.execute("SELECT COUNT(*) FROM background_monitor_events").fetchone()[0] == 4


def test_event_storage_bounds_oversized_evidence_and_keeps_metadata_valid(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    event = _event("oversized-event")
    event.evidence = "e" * 100_000
    event.metadata_json = '{"payload":"' + ("m" * 150_000) + '"}'

    db.record_background_monitor_event(event, dedupe_window_seconds=0)

    stored = db.latest_monitor_events(limit=1)[0]
    assert len(stored.evidence.encode("utf-8")) <= 65_536
    assert "truncated by MSAA" in stored.evidence
    metadata = json.loads(stored.metadata_json)
    assert metadata["storage_truncated"] is True
    assert metadata["original_bytes"] > 131_072


def test_flight_recorder_report_includes_correlation_id(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event(), dedupe_window_seconds=0)

    report = IntrusionCorrelationEngine(db).build_report(recent_limit=10)

    assert report.recent_events
    assert report.recent_events[0]["correlation_id"].startswith("corr-")
    assert report.ai_summary["event_timeline"][0]["correlation_id"].startswith("corr-")
