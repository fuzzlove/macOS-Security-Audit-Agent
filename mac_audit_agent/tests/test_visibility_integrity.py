from datetime import datetime, timedelta, timezone
from pathlib import Path

from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.visibility_integrity import VisibilityIntegrityEngine


def _old_timestamp(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def _fresh_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _component(payload: dict, name: str) -> dict:
    for item in payload["components"]:
        if item["component_name"] == name:
            return item
    raise AssertionError(f"missing component {name}")


def test_stale_heartbeat_lowers_score(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_monitor_heartbeat(_fresh_timestamp())
    fresh = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()

    db.record_monitor_heartbeat(_old_timestamp())
    stale = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()

    assert stale["score"] < fresh["score"]
    assert _component(stale, "Monitor Heartbeat")["status"] == "failing"


def test_notifier_not_running_lowers_score(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("notification_status", "not running")
    db.set_background_monitor_state("notifier_running", "0")
    payload = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()
    assert payload["score"] < 100
    assert _component(payload, "User Notifier Status")["status"] == "failing"


def test_db_failure_lowers_score(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.close()
    payload = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()
    assert payload["score"] < 100
    assert _component(payload, "SQLite Health")["status"] == "failing"


def test_detector_stale_status_appears(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("detector_last_run_timestamp", _old_timestamp(1800))
    for key in [
        "detector_enabled_camera",
        "detector_enabled_session",
        "detector_enabled_network",
        "detector_enabled_persistence",
        "detector_enabled_sharing",
        "detector_enabled_process",
        "detector_enabled_hardware",
    ]:
        db.set_background_monitor_state(key, "1")
    payload = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()
    detector = _component(payload, "Detector Freshness")
    assert detector["status"] == "degraded"
    assert "last ran" in detector["evidence"]


def test_report_includes_visibility_status(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    visibility = VisibilityIntegrityEngine(db, reports_dir=tmp_path / "reports").build_report().to_dict()
    scan = ScanResult(
        scan_id="scan-1",
        timestamp=_fresh_timestamp(),
        hostname="mac.local",
        current_user="m",
        collected_artifacts={
            "visibility_integrity": visibility,
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "localhost_scan": {},
            "processes": {"all": [], "suspicious": [], "errors": []},
        },
    )
    json_path = export_scan_result_json(scan, tmp_path / "report.json")
    html_path = export_scan_result_html(scan, tmp_path / "report.html")
    assert "visibility_integrity" in json_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    assert "Visibility Integrity" in html
    assert "Component Statuses" in html
