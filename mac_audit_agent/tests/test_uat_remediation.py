import json
from pathlib import Path

from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.quality.audit_models import AuditContext
from mac_audit_agent.quality.release_readiness import run_release_audit
from mac_audit_agent.reporting import export_scan_result_html
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase


def test_html_scan_export_always_includes_limitations(tmp_path: Path) -> None:
    from mac_audit_agent.quality.export_auditor import sample_scan_result

    path = export_scan_result_html(sample_scan_result(), tmp_path / "scan.html")
    text = Path(path).read_text(encoding="utf-8")

    assert '<section id="limitations">' in text
    assert "Limitations" in text
    assert "No material limitations were recorded for this report." in text


def test_safe_scan_physical_device_artifacts_have_explicit_status(monkeypatch) -> None:
    class FakeSnapshot:
        usb_devices = [{"name": "Test USB"}]
        bluetooth_devices = []
        nearby_bluetooth_devices = []

    class FakeHardwareMonitor:
        def collect_snapshot(self, *, include_usb: bool = True, include_bluetooth: bool = True):
            return FakeSnapshot()

    import mac_audit_agent.collectors as collectors

    monkeypatch.setattr(collectors, "HardwareMonitor", FakeHardwareMonitor)
    suite = CollectorSuite(SafeCommandRunner(RunnerConfig(dry_run=True)), AuditConfig(dry_run=True))

    physical = suite._collect_physical_device_artifacts({"architecture": "arm64"}, [])
    hardware = suite._collect_hardware_artifact({"architecture": "arm64"}, [])

    assert physical["status"] == "collected"
    assert isinstance(physical["usb_devices"], list)
    assert isinstance(physical["bluetooth_devices"], list)
    assert physical["known_usb_devices"] == physical["usb_devices"]
    assert "last_checked" in physical
    assert hardware["status"] in {"collected", "unavailable", "permission_limited", "unsupported"}
    assert hardware["architecture"] == "arm64"


def test_monitor_heartbeat_records_auditable_status_payload(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite")

    db.record_monitor_heartbeat(
        "2026-07-05T12:00:00+00:00",
        {
            "daemon_label": "com.mac-audit-agent.monitor",
            "pid": 123,
            "mode": "system-daemon",
            "db_path": str(db.path),
            "settings_version": 1,
            "detector_counts": {"hardware_device_detector": 0},
            "last_error": "",
        },
    )

    payload = json.loads(db.get_background_monitor_state("last_heartbeat_status_json", "{}"))
    assert db.latest_monitor_heartbeat() == "2026-07-05T12:00:00+00:00"
    assert payload["db_path"] == str(db.path)
    assert payload["mode"] == "system-daemon"
    assert payload["detector_counts"]["hardware_device_detector"] == 0


def test_db_path_alignment_flags_user_db_when_system_daemon_is_active(tmp_path: Path, monkeypatch) -> None:
    import mac_audit_agent.runtime.db_path_resolver as resolver

    user_db_path = tmp_path / "user.sqlite"
    system_db_path = tmp_path / "system.sqlite"
    AuditDatabase(system_db_path).record_monitor_heartbeat("2026-07-05T12:00:00+00:00")
    AuditDatabase(user_db_path).set_background_monitor_state("monitor_mode", "system")

    def fake_default_monitor_db_path(scope: str | None = None) -> Path:
        return system_db_path if scope == "system" else user_db_path

    monkeypatch.setattr(resolver, "default_monitor_db_path", fake_default_monitor_db_path)
    monkeypatch.setattr(__import__("mac_audit_agent.runtime.topology", fromlist=["SYSTEM_DB"]), "SYSTEM_DB", system_db_path)

    alignment = resolver.validate_db_path_alignment(
        settings_db_path=user_db_path,
        notifier_db_path=user_db_path,
        event_db_path=user_db_path,
        alert_trace_db_path=user_db_path,
    )

    assert alignment.active_monitor_mode == "system"
    assert alignment.active_monitor_db_path == str(system_db_path)
    assert alignment.aligned is False
    assert set(alignment.mismatches) == {
        "notifier_db_path",
        "active_event_db_path",
        "alert_trace_db_path",
    }


def test_release_readiness_audit_reports_blocked_release_without_blocking_manual_uat(tmp_path: Path, monkeypatch) -> None:
    class FakeReport:
        def to_dict(self):
            return {
                "generated_at": "2026-07-05T12:00:00+00:00",
                "score": 80,
                "status": "blocked",
                "checks": [{"name": "user notifier audit passes", "status": "block"}],
            }

    class FakeEngine:
        def __init__(self, db):
            self.db = db

        def build_report(self, *, run_expensive: bool = False):
            return FakeReport()

    import mac_audit_agent.quality.release_readiness as release_readiness

    monkeypatch.setattr(release_readiness, "ReleaseReadinessEngine", FakeEngine)
    context = AuditContext(db_path=tmp_path / "audit.sqlite", output_dir=tmp_path)

    checks = run_release_audit(context)

    assert checks[0].check_id == "release.readiness_report_generated"
    assert checks[0].status == "PASS"
    assert checks[0].evidence["release_readiness_report_generated"] is True
    assert checks[0].evidence["release_status"] == "blocked"
    assert checks[0].evidence["release_ready_for_public_distribution"] is False
    assert checks[0].evidence["release_blocking_count"] == 1
    assert checks[1].check_id == "release.public_distribution_gate"
    assert checks[1].status == "BLOCKER"


def test_pre_uat_audit_rejects_duplicate_check_ids(tmp_path: Path) -> None:
    import pytest
    from mac_audit_agent.quality.audit_models import AuditReport, FunctionalCheck
    from mac_audit_agent.quality.pre_uat_audit import _add_unique_check

    report = AuditReport(run_id="test", hostname="host", started_at="2026-07-05T12:00:00+00:00")
    first = FunctionalCheck("exports.word", "Exports", "Word", "Word export").passed("ok")
    duplicate = FunctionalCheck("exports.word", "Exports", "Word", "Word export", "high").failed("missing dependency", "Install dependency.")

    _add_unique_check(report, first)
    with pytest.raises(ValueError, match="duplicate check ID rejected: exports.word"):
        _add_unique_check(report, duplicate)

    assert len(report.checks) == 1
    assert report.checks[0].check_id == "exports.word"
    assert report.checks[0].status == "PASS"


def test_alert_trace_storage_prevents_overlay_success_when_event_store_failed(tmp_path: Path) -> None:
    from mac_audit_agent.models import EventAlertTrace

    db = AuditDatabase(tmp_path / "audit.sqlite")
    trace = EventAlertTrace(
        trace_id="trace-1",
        event_id="event-1",
        event_type="critical_test_event",
        stored_success=False,
        overlay_dispatch_attempted=True,
        overlay_dispatch_result="SUCCESS",
        visible_alert_id="visible-1",
    )

    db.record_event_alert_trace(trace)
    stored = db.get_event_alert_trace("event-1")

    assert stored is not None
    payload = stored.to_dict()
    assert payload["event_written_to_db"] is False
    assert payload["overlay_dispatch_attempted"] is False
    assert payload["overlay_dispatch_result"] == ""
    assert payload["visible_alert_id"] == ""
    assert payload["trace_consistency_status"] == "event_store_failed"
