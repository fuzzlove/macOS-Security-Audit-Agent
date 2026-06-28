from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent import reliability
from mac_audit_agent.models import AlertPipelineTrace, BackgroundMonitorEvent, EventAlertTrace, Finding
from mac_audit_agent.notification_manager import MANDATORY_VISIBLE_ALERT_EVENT_TYPES, NotificationManager
from mac_audit_agent.reliability import (
    AlertPipelineInspector,
    ConfigurationDriftEngine,
    IncidentModeManager,
    MonitoringCoverageEngine,
    ReleaseReadinessEngine,
    TrustDecayEngine,
    export_sarif,
    mandatory_alert_policy_gaps,
)
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.reliability_panel import ReliabilityPanel


def _db(tmp_path: Path) -> AuditDatabase:
    return AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")


def _event(event_id: str, event_type: str, severity: str = "high") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id=event_id,
        timestamp="2026-06-16T12:00:00+00:00",
        event_type=event_type,
        severity=severity,
        source="test",
        evidence=f"{event_type} evidence",
        confidence="high",
        recommendation="review",
        rule_id=event_type,
    )


def test_alert_pipeline_health_reports_failure_stage_and_counts(tmp_path: Path) -> None:
    db = _db(tmp_path)
    event = _event("event-1", "usb_device_connected", "medium")
    db.record_background_monitor_event(event)
    db.record_event_alert_trace(
        EventAlertTrace(
            trace_id="trace-event-1",
            event_id="event-1",
            event_type="usb_device_connected",
            original_event_type="usb_device_connected",
            normalized_event_type="usb_device_connected",
            detector_source="usb",
            stored_db_path=str(db.path),
            stored_success=True,
            notifier_db_path=str(db.path),
            notifier_seen=True,
            notifier_seen_at="2026-06-16T12:00:01+00:00",
            notification_policy_checked=True,
            notification_policy_result="suppressed_cooldown",
            notification_policy_reason="within_cooldown",
            alert_required=True,
            alert_suppressed=True,
            alert_suppression_reason="within_cooldown",
        )
    )

    health = AlertPipelineInspector(db).build_health()

    assert health.suppressed_count == 1
    assert health.db_path_mismatch_status == "match"
    assert health.last_failure_stage == "suppressed:within_cooldown"


def test_alert_pipeline_trace_exports_required_field_names() -> None:
    trace = AlertPipelineTrace(
        trace_id="trace-1",
        event_id="event-1",
        event_type="usb_reconnect_detected",
        original_event_type="usb_reconnect_detected",
        normalized_event_type="usb_device_connected",
        detector_source="hardware_detector",
        stored_db_path="/tmp/audit.sqlite",
        stored_success=True,
        notification_policy_checked=True,
        notification_policy_result="sent",
        notification_policy_reason="mandatory_visible",
        alert_suppression_reason="",
    )

    payload = trace.to_dict()

    assert payload["canonical_event_type"] == "usb_device_connected"
    assert payload["db_path_written"] == "/tmp/audit.sqlite"
    assert payload["policy_checked"] is True
    assert payload["policy_result"] == "sent"
    assert payload["policy_reason"] == "mandatory_visible"
    assert payload["suppression_reason"] == ""


def test_mandatory_visible_alert_policy_covers_required_high_value_events() -> None:
    required = {
        "lid_opened",
        "lid_closed",
        "display_wake",
        "display_sleep",
        "screen_unlocked",
        "screen_locked",
        "idle_resume_detected",
        "mouse_or_keyboard_activity_after_idle",
        "usb_device_connected",
        "usb_device_removed",
        "new_usb_device_detected",
        "bluetooth_device_connected",
        "bluetooth_device_disconnected",
        "bluetooth_inventory_changed",
        "new_network_connection_detected",
        "remote_login_enabled",
        "screen_sharing_enabled",
        "launchagent_added",
        "launchdaemon_added",
        "new_admin_user_detected",
        "protected_monitor_tamper_detected",
    }

    assert required.issubset(MANDATORY_VISIBLE_ALERT_EVENT_TYPES)


def test_mandatory_alert_policy_gaps_empty_for_default_settings(tmp_path: Path) -> None:
    db = _db(tmp_path)

    assert mandatory_alert_policy_gaps(db) == []


def test_mandatory_alert_policy_gaps_report_disabled_category(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state("show_network_change_alerts", "0")

    gaps = mandatory_alert_policy_gaps(db)

    assert "new_network_connection_detected:category_disabled:network" in gaps


def test_mandatory_alert_policy_reports_explicit_disabled_preference(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "event_preferences_json",
        json.dumps(
            {
                "suspicious_process_observed": {
                    "enabled": False,
                    "severity": "high",
                    "notify": False,
                    "notification_mode": "none",
                    "cooldown_seconds": 600,
                }
            },
            sort_keys=True,
        ),
    )

    gaps = mandatory_alert_policy_gaps(db)

    assert "suspicious_process_observed:disabled_by_preference" in gaps
    assert "suspicious_process_observed:notify_false" in gaps
    assert "suspicious_process_observed:notification_mode_none" in gaps


def test_explicit_disabled_preference_disables_mandatory_alert_decision(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "event_preferences_json",
        json.dumps(
            {
                "suspicious_process_observed": {
                    "enabled": False,
                    "severity": "high",
                    "notify": False,
                    "notification_mode": "none",
                    "cooldown_seconds": 600,
                }
            },
            sort_keys=True,
        ),
    )
    event = _event("mandatory-preference-1", "suspicious_process_observed", "high")

    decision = NotificationManager(db).evaluate_notification_decision(event)

    assert decision["decision"] == "disabled_by_user"
    assert decision["reason"] == "event_disabled_by_preference"
    assert decision["alert_suppressed_reason"] == "event_disabled_by_preference"


def test_reliability_panel_shows_recent_alert_trace_rows() -> None:
    app = QApplication.instance() or QApplication([])
    panel = ReliabilityPanel()
    panel.set_payload(
        {
            "alert_pipeline": {
                "traces": [
                    {
                        "trace_id": "trace-1",
                        "event_id": "event-1",
                        "original_event_type": "usb_reconnect_detected",
                        "canonical_event_type": "usb_device_connected",
                        "detector_source": "hardware_detector",
                        "stored_success": True,
                        "notifier_seen": True,
                        "policy_result": "sent",
                        "policy_reason": "mandatory_visible",
                        "cooldown_result": "elapsed",
                        "suppression_reason": "",
                        "alert_required": True,
                        "alert_queue_enqueued": True,
                        "overlay_dispatch_result": "SUCCESS",
                        "visible_alert_id": "event-1",
                        "displayed_at": "2026-06-16T12:00:00+00:00",
                    }
                ]
            },
            "monitoring_coverage": {
                "score": 100,
                "components": [
                    {
                        "component": "USB detector",
                        "status": "healthy",
                        "last_successful_run": "2026-06-16T12:00:00+00:00",
                        "last_event": "2026-06-16T12:00:01+00:00 usb_device_connected",
                        "last_error": "",
                        "heartbeat_age_seconds": 5,
                        "permission_status": "available",
                        "failure_reason": "",
                        "recommended_fix": "No action required.",
                    }
                ],
            },
            "release_readiness": {"ReleaseReadinessScore": 100, "status": "ready", "checks": []},
            "trust_decay": {"current_score": 100, "trend": "stable", "timeline": []},
            "configuration_drift": {"changes": []},
            "incident_mode": {
                "active": True,
                "banner": "Incident Mode Active - Preserve evidence before cleanup or remediation.",
                "recommended_actions": ["Create Evidence Snapshot"],
                "evidence_snapshot_count": 1,
                "case_package_count": 1,
                "investigation_note_count": 1,
                "last_evidence_snapshot": {"path": "/tmp/snapshot.json"},
                "last_case_package": {"path": "/tmp/case.html"},
            },
        }
    )

    assert panel.trace_table.rowCount() == 1
    assert panel.trace_table.item(0, 3).text() == "usb_device_connected"
    assert panel.trace_table.item(0, 12).text().startswith("SUCCESS")
    assert panel.coverage_table.item(0, 5).text() == "5"
    assert panel.coverage_table.item(0, 6).text() == "available"
    assert panel.incident_snapshot_button.text() == "Create Evidence Snapshot"
    assert panel.incident_timeline_button.text() == "Open Timeline"
    assert panel.incident_export_button.text() == "Export Case Package"
    assert panel.incident_note_button.text() == "Add Investigation Note"
    assert panel.incident_priority_button.text() == "Review High Priority Events"
    assert "Evidence snapshots: 1" in panel.incident_text.toPlainText()
    assert "/tmp/case.html" in panel.incident_text.toPlainText()
    assert app is not None


def test_monitoring_coverage_score_surfaces_component_problems(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state("detector_enabled_hardware", "1")
    db.set_background_monitor_state("detector_last_run_timestamp", "2026-06-16T12:00:00+00:00")
    db.record_background_monitor_event(_event("usb-1", "usb_device_connected", "medium"))
    db.record_monitor_heartbeat("2026-06-16T12:00:00+00:00")
    report = MonitoringCoverageEngine(db, reports_dir=tmp_path / "reports").build_report()
    payload = report.to_dict()

    assert 0 <= report.score <= 100
    assert payload["MonitoringCoverageScore"] == report.score
    assert payload["score"] == report.score
    assert any(component.component == "USB detector" for component in report.components)
    assert any(component.component == "SQLite storage" and component.status == "healthy" for component in report.components)


def test_monitoring_coverage_flags_unwritable_default_alert_overlay_state_with_fallback(tmp_path: Path, monkeypatch) -> None:
    db = _db(tmp_path)
    overlay_state_path = tmp_path / "state" / "security_overlay.json"

    original_write_text = Path.write_text

    def fail_overlay_probe(self: Path, *args, **kwargs):
        if self.parent == overlay_state_path.parent and self.name == ".msaa_overlay_write_test":
            raise PermissionError("overlay state denied")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_overlay_probe)

    report = MonitoringCoverageEngine(db, reports_dir=tmp_path / "reports", overlay_state_path=overlay_state_path).build_report()
    overlay = next(component for component in report.components if component.component == "Alert overlay")

    assert overlay.status == "degraded"
    assert "overlay state denied" in overlay.failure_reason
    assert "Repair ownership and permissions" in overlay.recommended_fix


def test_release_readiness_report_has_score_status_and_checks(tmp_path: Path) -> None:
    db = _db(tmp_path)
    report = ReleaseReadinessEngine(db).build_report(run_expensive=False)
    check_names = {check.check for check in report.checks}

    assert 0 <= report.score <= 100
    assert report.status in {"ready", "needs work", "blocked"}
    assert {
        "PyPI metadata valid",
        "Python runtime supports package metadata",
        "clean wheel install verified",
        "reports export",
        "system daemon audit passes",
        "user notifier audit passes",
        "Apple Exposure Assessment works or degrades cleanly",
        "alert pipeline passes synthetic event test",
        "python -m build passes",
        "twine check passes",
    }.issubset(check_names)


def test_release_readiness_pyproject_check_uses_installed_metadata_when_pyproject_missing(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "installed"
    repo_root.mkdir()

    class FakeMetadata:
        def get(self, key: str, default: str = "") -> str:
            return {
                "Name": "macos-security-audit-agent",
                "Requires-Python": ">=3.10",
            }.get(key, default)

    class FakeEntryPoint:
        group = "console_scripts"
        name = "macos-security-audit-agent"
        value = "mac_audit_agent.cli:main"

    class FakeDistribution:
        entry_points = [FakeEntryPoint()]

    monkeypatch.setattr(reliability.importlib.metadata, "metadata", lambda _name: FakeMetadata())
    monkeypatch.setattr(reliability.importlib.metadata, "distribution", lambda _name: FakeDistribution())

    check = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._pyproject_check()

    assert check.status == "pass"
    assert "installed package metadata" in check.evidence


def test_release_readiness_installed_mode_does_not_block_on_source_docs(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "installed"
    repo_root.mkdir()

    class FakeMetadata:
        def get(self, key: str, default: str = "") -> str:
            return {
                "Description": "Long description from packaged README.",
                "License-Expression": "MIT",
            }.get(key, default)

    monkeypatch.setattr(reliability.importlib.metadata, "metadata", lambda _name: FakeMetadata())

    checks = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._documentation_checks()
    by_name = {check.check: check for check in checks}

    assert by_name["README exists"].status == "pass"
    assert by_name["LICENSE exists"].status == "pass"
    assert by_name["SECURITY.md exists"].status == "needs work"
    assert by_name["Privacy documentation exists"].status == "needs work"
    assert by_name["Uninstall instructions exist"].status == "needs work"
    assert all(check.status != "block" for check in checks)


def test_release_readiness_quick_mode_accepts_recent_saved_gate_evidence(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ReleaseReadinessEngine(db)
    engine._record_release_gate_check(
        "tests_pass",
        reliability.ReleaseReadinessCheck("tests pass", "pass", "570 passed", "Run pytest before release."),
    )

    check = engine._saved_release_gate_check("tests_pass", "tests pass", "Run pytest before release.")

    assert check.status == "pass"
    assert "570 passed" in check.evidence


def test_release_readiness_quick_mode_rejects_stale_saved_gate_evidence(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "release_readiness_gate:tests_pass",
        json.dumps(
            {
                "generated_at": "2000-01-01T00:00:00+00:00",
                "check": {"check": "tests pass", "status": "pass", "evidence": "old pass", "recommended_fix": "Run pytest before release."},
            },
            sort_keys=True,
        ),
    )

    check = ReleaseReadinessEngine(db)._saved_release_gate_check("tests_pass", "tests pass", "Run pytest before release.")

    assert check.status == "needs work"
    assert "stale" in check.evidence


def test_release_readiness_clean_install_requires_saved_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    check = ReleaseReadinessEngine(db)._clean_install_check()

    assert check.status == "needs work"
    assert "No clean install verification report" in check.evidence


def test_release_readiness_accepts_clean_install_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "clean_install_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "python": "/opt/python3.12/bin/python",
                "wheel": "dist/macos_security_audit_agent-0.1.0-py3-none-any.whl",
                "stages": [
                    {"check_id": "python_version", "status": "PASS"},
                    {"check_id": "wheel_exists", "status": "PASS"},
                    {"check_id": "venv_create", "status": "PASS"},
                    {"check_id": "wheel_install", "status": "PASS"},
                    {"check_id": "import_sweep", "status": "PASS"},
                    {"check_id": "resource_check", "status": "PASS"},
                    {"check_id": "console_help", "status": "PASS"},
                    {"check_id": "release_readiness_cli", "status": "PASS"},
                ],
            },
            sort_keys=True,
        ),
    )

    assert ReleaseReadinessEngine(db)._clean_install_check().status == "pass"


def test_release_readiness_blocks_failed_clean_install_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "clean_install_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "python": "/usr/bin/python3",
                "wheel": "dist/macos_security_audit_agent-0.1.0-py3-none-any.whl",
                "stages": [
                    {"check_id": "python_version", "status": "FAIL"},
                    {"check_id": "wheel_exists", "status": "PASS"},
                ],
            },
            sort_keys=True,
        ),
    )

    check = ReleaseReadinessEngine(db)._clean_install_check()

    assert check.status == "block"
    assert "python_version" in check.evidence


def test_release_readiness_pytest_check_forces_qt_offscreen(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, str] = {}
    expected_command = ["python3", "-m", "pytest", "mac_audit_agent/tests", "-q"]

    class FakeResult:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        if command == expected_command:
            assert kwargs["timeout"] == reliability.RELEASE_PYTEST_TIMEOUT_SECONDS
            captured.update(kwargs["env"])
        return FakeResult()

    monkeypatch.delenv("QT_QPA_PLATFORM", raising=False)
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/release-venv")
    monkeypatch.setattr(reliability.subprocess, "run", fake_run)

    check = ReleaseReadinessEngine(_db(tmp_path))._pytest_check()

    assert check.status == "pass"
    assert captured
    assert captured["QT_QPA_PLATFORM"] == "offscreen"
    assert "VIRTUAL_ENV" not in captured


def test_release_readiness_pytest_check_uses_configured_python(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    class FakeResult:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append([str(item) for item in command])
        return FakeResult()

    monkeypatch.setattr(reliability.subprocess, "run", fake_run)

    check = ReleaseReadinessEngine(_db(tmp_path), pytest_python="/opt/homebrew/bin/python3.12")._pytest_check()

    assert check.status == "pass"
    assert calls[0][:3] == ["/opt/homebrew/bin/python3.12", "-m", "pytest"]


def test_release_readiness_expensive_package_checks_use_build_and_twine(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    dist = repo_root / "dist"
    dist.mkdir(parents=True)
    wheel = dist / "macos_security_audit_agent-0.1.1-py3-none-any.whl"
    wheel.write_text("placeholder", encoding="utf-8")
    calls: list[list[str]] = []

    class FakeResult:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append([str(item) for item in command])
        return FakeResult()

    monkeypatch.setattr(reliability.subprocess, "run", fake_run)
    engine = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)

    assert engine._build_check().status == "pass"
    assert engine._twine_check().status == "pass"
    assert any(call[:3] == [reliability.sys.executable, "-m", "build"] for call in calls)
    assert any(call[:4] == [reliability.sys.executable, "-m", "twine", "check"] and str(wheel) in call for call in calls)


def test_release_readiness_build_check_uses_backend_capable_fallback(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    calls: list[list[str]] = []

    class FakeResult:
        def __init__(self, returncode: int = 0, stdout: str = "ok", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, **kwargs):
        rendered = [str(item) for item in command]
        calls.append(rendered)
        if rendered == [reliability.sys.executable, "-c", "import build"]:
            return FakeResult()
        if rendered == [reliability.sys.executable, "-m", "build"]:
            return FakeResult(returncode=1, stderr="Could not find a version that satisfies the requirement wheel")
        if rendered == [reliability.sys.executable, "-c", "import build; import setuptools.build_meta"]:
            return FakeResult(returncode=1, stderr="No module named setuptools")
        if rendered[-2:] == ["-c", "import build; import setuptools.build_meta"]:
            return FakeResult()
        if rendered[-3:] == ["-m", "build", "--no-isolation"]:
            return FakeResult(stdout="fallback build ok")
        return FakeResult()

    monkeypatch.setattr(reliability.subprocess, "run", fake_run)

    check = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._build_check()

    assert check.status == "pass"
    assert any(call[-3:] == ["-m", "build", "--no-isolation"] for call in calls)
    assert "no-isolation fallback" in check.evidence


def test_release_readiness_twine_check_blocks_without_dist_artifacts(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    check = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._twine_check()

    assert check.status == "block"
    assert "No dist artifacts" in check.evidence


def test_release_readiness_twine_check_uses_current_python_artifacts_only(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    dist = repo_root / "dist"
    dist.mkdir(parents=True)
    (dist / "macos_security_audit_agent-0.1.0-py3-none-any.whl").write_text("old", encoding="utf-8")
    (dist / "macos_security_audit_agent-0.1.0.tar.gz").write_text("old", encoding="utf-8")
    (dist / "MSAA-0.1.1-macos-universal.zip").write_text("app", encoding="utf-8")
    current_wheel = dist / "macos_security_audit_agent-0.1.1-py3-none-any.whl"
    current_sdist = dist / "macos_security_audit_agent-0.1.1.tar.gz"
    current_wheel.write_text("wheel", encoding="utf-8")
    current_sdist.write_text("sdist", encoding="utf-8")
    calls: list[list[str]] = []

    class FakeResult:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(ReleaseReadinessEngine, "_python_with_module", lambda self, module: "python")

    def fake_run(command: list[str], **kwargs: object) -> FakeResult:
        calls.append(command)
        return FakeResult()

    monkeypatch.setattr(reliability.subprocess, "run", fake_run)

    check = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._twine_check()

    assert check.status == "pass"
    assert calls == [["python", "-m", "twine", "check", str(current_wheel), str(current_sdist)]]


def test_release_readiness_reports_export_check_includes_sarif(tmp_path: Path) -> None:
    db = _db(tmp_path)
    check = ReleaseReadinessEngine(db)._reports_export_check()

    assert check.status == "pass"
    assert "SARIF" in check.evidence


def test_release_readiness_blocks_placeholder_production_ui_source(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    ui_dir = repo_root / "mac_audit_agent" / "ui"
    ui_dir.mkdir(parents=True)
    (ui_dir / "bad_panel.py").write_text('from PySide6.QtWidgets import QPushButton\nbutton = QPushButton("Placeholder Action")\n', encoding="utf-8")

    check = ReleaseReadinessEngine(_db(tmp_path), repo_root=repo_root)._production_ui_check()

    assert check.status == "block"
    assert "Placeholder Action" in check.evidence


def test_release_readiness_alert_pipeline_requires_successful_trace(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ReleaseReadinessEngine(db)

    check = engine._alert_pipeline_check()

    assert check.status == "needs work"

    event = _event("trace-pass", "lid_opened")
    db.record_background_monitor_event(event)
    db.record_event_alert_trace(
        EventAlertTrace(
            trace_id="trace-trace-pass",
            event_id="trace-pass",
            event_type="lid_opened",
            original_event_type="lid_opened",
            normalized_event_type="lid_opened",
            detector_source="session_detector",
            stored_db_path=str(db.path),
            stored_success=True,
            notifier_db_path=str(db.path),
            notifier_seen=True,
            notifier_seen_at="2026-06-16T12:00:01+00:00",
            notification_policy_checked=True,
            notification_policy_result="sent",
            notification_policy_reason="mandatory_visible",
            alert_required=True,
            overlay_dispatch_attempted=True,
            overlay_dispatch_result="SUCCESS",
            visible_alert_id="trace-pass",
            displayed_at="2026-06-16T12:00:02+00:00",
        )
    )

    assert engine._alert_pipeline_check().status == "pass"


def test_release_readiness_alert_pipeline_reports_mandatory_policy_gaps(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state("show_network_change_alerts", "0")
    event = _event("trace-pass", "lid_opened")
    db.record_background_monitor_event(event)
    db.record_event_alert_trace(
        EventAlertTrace(
            trace_id="trace-trace-pass",
            event_id="trace-pass",
            event_type="lid_opened",
            original_event_type="lid_opened",
            normalized_event_type="lid_opened",
            detector_source="session_detector",
            stored_db_path=str(db.path),
            stored_success=True,
            notifier_db_path=str(db.path),
            notifier_seen=True,
            notifier_seen_at="2026-06-16T12:00:01+00:00",
            notification_policy_checked=True,
            notification_policy_result="sent",
            notification_policy_reason="mandatory_visible",
            alert_required=True,
            overlay_dispatch_attempted=True,
            overlay_dispatch_result="SUCCESS",
            visible_alert_id="trace-pass",
            displayed_at="2026-06-16T12:00:02+00:00",
        )
    )

    check = ReleaseReadinessEngine(db)._alert_pipeline_check()

    assert check.status == "needs work"
    assert "mandatory_alert_policy_gaps" in check.evidence
    assert "category_disabled:network" in check.evidence


def test_release_readiness_alert_pipeline_accepts_event_flow_verification(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "deployment_event_flow_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "request_id": "flow-1",
                "stages": [
                    {"check_id": "detector_writes_event", "status": "PASS"},
                    {"check_id": "notifier_receives_event", "status": "PASS"},
                    {"check_id": "overlay_displays_event", "status": "PASS"},
                ],
            },
            sort_keys=True,
        ),
    )

    check = ReleaseReadinessEngine(db)._alert_pipeline_check()

    assert check.status == "pass"
    assert "deployment_event_flow" in check.evidence


def test_release_readiness_rejects_daemon_only_event_flow_verification(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "deployment_event_flow_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "request_id": "flow-1",
                "stages": [
                    {"check_id": "daemon_wrote_event", "status": "PASS"},
                    {"check_id": "shared_db_receives_event", "status": "PASS"},
                    {"check_id": "notifier_receives_event", "status": "PASS"},
                    {"check_id": "visible_alert_delivery", "status": "WARNING"},
                ],
            },
            sort_keys=True,
        ),
    )

    check = ReleaseReadinessEngine(db)._alert_pipeline_check()

    assert check.status == "needs work"


def test_release_readiness_accepts_visible_alert_verification_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "visible_alert_verification_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "event_id": "visible-1",
                "event_type": "lid_opened",
                "stages": [
                    {"check_id": "sqlite_store", "status": "PASS"},
                    {"check_id": "notifier_policy_checked", "status": "PASS"},
                    {"check_id": "overlay_dispatch", "status": "PASS"},
                    {"check_id": "visible_alert_delivery", "status": "PASS"},
                ],
            },
            sort_keys=True,
        ),
    )

    check = ReleaseReadinessEngine(db)._alert_pipeline_check()

    assert check.status == "pass"
    assert "visible_alert_verification" in check.evidence


def test_release_readiness_rejects_failed_visible_alert_verification_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "visible_alert_verification_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "event_id": "visible-1",
                "event_type": "lid_opened",
                "stages": [
                    {"check_id": "sqlite_store", "status": "PASS"},
                    {"check_id": "notifier_policy_checked", "status": "PASS"},
                    {"check_id": "overlay_dispatch", "status": "FAIL"},
                    {"check_id": "visible_alert_delivery", "status": "FAIL"},
                ],
            },
            sort_keys=True,
        ),
    )

    assert ReleaseReadinessEngine(db)._alert_pipeline_check().status == "needs work"


def test_release_readiness_rejects_non_mandatory_visible_alert_verification_report(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state(
        "visible_alert_verification_last_report_json",
        json.dumps(
            {
                "generated_at": "2026-06-16T12:00:00+00:00",
                "event_id": "visible-1",
                "event_type": "routine_status",
                "stages": [
                    {"check_id": "sqlite_store", "status": "PASS"},
                    {"check_id": "notifier_policy_checked", "status": "PASS"},
                    {"check_id": "overlay_dispatch", "status": "PASS"},
                    {"check_id": "visible_alert_delivery", "status": "PASS"},
                ],
            },
            sort_keys=True,
        ),
    )

    assert ReleaseReadinessEngine(db)._alert_pipeline_check().status == "needs work"


def test_trust_decay_records_delta_and_causes(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state("trust_score_current", "100")
    db.record_background_monitor_event(_event("daemon-1", "launchdaemon_added", "critical"))

    report = TrustDecayEngine(db).build_report()

    assert report["current_score"] < 100
    assert report["trend"] == "declining"
    assert report["timeline"][0]["event_type"] == "launchdaemon_added"
    assert report["score_history"][0]["previous_score"] == 100
    assert report["score_history"][0]["current_score"] == report["current_score"]
    assert report["score_history"][0]["related_events"][0]["event_id"] == "daemon-1"


def test_trust_decay_history_is_not_duplicated_on_refresh(tmp_path: Path) -> None:
    db = _db(tmp_path)
    db.set_background_monitor_state("trust_score_current", "100")
    db.record_background_monitor_event(_event("usb-1", "new_usb_device_detected", "critical"))
    engine = TrustDecayEngine(db)

    first = engine.build_report()
    second = engine.build_report()
    stored_history = json.loads(db.get_background_monitor_state("trust_score_history_json", "[]"))

    assert first["delta"] < 0
    assert second["delta"] == 0
    assert len(stored_history) == 1
    assert stored_history[0]["current_score"] == first["current_score"]


def test_configuration_drift_detects_changed_security_setting(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ConfigurationDriftEngine(db)
    engine.update_snapshot({"remote_login": "Disabled"})
    report = engine.update_snapshot({"remote_login": "Enabled"})

    assert report["changes"]
    change = report["changes"][0]
    assert change["setting"] == "Remote Login / SSH"
    assert change["severity"] == "high"
    assert change["previous_value"] == "Disabled"
    assert change["current_value"] == "Enabled"
    assert change["previous_value_json"] == '"Disabled"'
    assert change["current_value_json"] == '"Enabled"'
    assert change["confidence"] == "medium"
    assert engine.timeline()["changes"][0]["change_id"] == change["change_id"]


def test_configuration_drift_skips_unknown_first_observations(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ConfigurationDriftEngine(db)

    report = engine.update_snapshot({"remote_login": "", "dns_servers": []})

    assert report["changes"] == []
    assert engine.timeline()["changes"] == []
    assert db.get_background_monitor_state("config_drift:remote_login", "") == ""


def test_configuration_drift_marks_unknown_after_known_low_confidence(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ConfigurationDriftEngine(db)
    engine.update_snapshot({"remote_login": True}, source_detector="sharing_detector")

    report = engine.update_snapshot({"remote_login": ""}, source_detector="sharing_detector")

    change = report["changes"][0]
    assert change["previous_value"] == "Enabled"
    assert change["current_value"] == "unknown/unobserved"
    assert change["confidence"] == "low"


def test_configuration_drift_displays_list_values(tmp_path: Path) -> None:
    db = _db(tmp_path)
    engine = ConfigurationDriftEngine(db)
    engine.update_snapshot({"dns_servers": ["1.1.1.1"]})

    report = engine.update_snapshot({"dns_servers": ["1.1.1.1", "8.8.8.8"]})

    assert report["changes"][0]["current_value"] == "1.1.1.1, 8.8.8.8"


def test_incident_mode_blocks_cleanup_until_disabled(tmp_path: Path) -> None:
    manager = IncidentModeManager(_db(tmp_path))
    manager.set_enabled(True)

    allowed, reason = manager.cleanup_allowed()
    assert allowed is False
    assert "Incident Mode active" in reason

    manager.set_enabled(False)
    assert manager.cleanup_allowed()[0] is True


def test_incident_mode_records_preservation_activity(tmp_path: Path) -> None:
    manager = IncidentModeManager(_db(tmp_path))
    manager.set_enabled(True)

    manager.record_evidence_snapshot("/tmp/evidence.json", reason="manual")
    manager.record_case_package_export("/tmp/case.html", format="html")
    manager.record_note_panel_opened()
    status = manager.status()

    assert status["evidence_snapshot_encouraged"] is True
    assert status["cleanup_actions_require_confirmation"] is True
    assert status["evidence_snapshot_count"] == 1
    assert status["last_evidence_snapshot"]["path"] == "/tmp/evidence.json"
    assert status["case_package_count"] == 1
    assert status["last_case_package"]["path"] == "/tmp/case.html"
    assert status["investigation_note_count"] == 1
    assert status["notes_panel_opened"] is True


def test_sarif_export_maps_findings_and_redacts_paths(tmp_path: Path) -> None:
    finding = Finding(
        id="finding-1",
        category="Persistence",
        title="LaunchDaemon added",
        severity="high",
        description="A new LaunchDaemon was found at /Users/alice/Library/LaunchAgents/test.plist?token=secret-token.",
        evidence="/Users/alice/Library/LaunchAgents/test.plist?token=secret-token",
        command_used="launchctl",
        remediation_suggestion="Review /Users/alice/Library/LaunchAgents/test.plist?token=secret-token.",
        warning="Preserve evidence before removing it.",
        rule_id="msaa.persistence.launchdaemon",
        related_path="/Users/alice/Library/LaunchAgents/test.plist",
        confidence="high",
    )

    path = export_sarif([finding], tmp_path / "report.sarif")
    payload = json.loads(path.read_text(encoding="utf-8"))

    result = payload["runs"][0]["results"][0]
    assert payload["version"] == "2.1.0"
    assert result["ruleId"] == "msaa.persistence.launchdaemon"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "[redacted-path]"
    serialized = json.dumps(result)
    assert "/Users/alice" not in serialized
    assert "secret-token" not in serialized
    assert "[REDACTED]" in serialized
