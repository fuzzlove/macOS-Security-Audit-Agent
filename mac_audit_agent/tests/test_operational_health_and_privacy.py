from __future__ import annotations

from pathlib import Path

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.operational_health import HealthCheck, OperationalHealthEngine, analyze_operational_health
from mac_audit_agent.privacy import redact_text, redact_structure
from mac_audit_agent.rules import rule_registry_summary, validate_rule_registry
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.source_integrity import record_source_integrity_baseline


class _FakeStatus:
    def __init__(self, *, installed: bool, loaded: bool, running: bool, plist_path: str = "", last_error: str = "") -> None:
        self.installed = installed
        self.loaded = loaded
        self.running = running
        self.plist_path = plist_path
        self.last_error = last_error


class _FakeLaunchAgent:
    def __init__(self, *, installed: bool = True, loaded: bool = True, running: bool = True, plist_path: str = "/tmp/test.plist") -> None:
        self._status = _FakeStatus(installed=installed, loaded=loaded, running=running, plist_path=plist_path)

    def status(self) -> _FakeStatus:
        return self._status


class _FakeReadinessReport:
    def __init__(self) -> None:
        self.deployment_state = "Healthy"
        self.health_score = 95


class _FakeReadiness:
    def audit_deployment(self) -> _FakeReadinessReport:
        return _FakeReadinessReport()


class _PermissionDeniedReadiness:
    def audit_deployment(self) -> _FakeReadinessReport:
        raise PermissionError(1, "Operation not permitted", "/Library/Caches/com.apple.amsengagement.classicdatavault")


class _FakeRadar:
    def load_cached_state(self) -> dict[str, object]:
        return {
            "catalog_update_status": "cached",
            "display_cards": [],
            "cards_count": 0,
            "errors": [],
        }


class _FakeNotifier:
    def status(self) -> str:
        return "available via AppleScript"


def test_privacy_redaction_helper_redacts_sensitive_observables() -> None:
    text = "host=example.local hostname=lab-mac alice 192.168.1.10 00:11:22:33:44:55 /Users/alice/Library"
    redacted = redact_text(text)
    assert "[REDACTED_HOSTNAME]" in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_MAC]" in redacted
    assert "[REDACTED_USER]" in redacted
    assert "alice" not in redacted

    payload = {
        "hostname": "lab-mac.local",
        "mac_address": "00:11:22:33:44:55",
        "path": "/Users/alice/Documents",
    }
    redacted_payload = redact_structure(payload)
    assert redacted_payload["hostname"] == "[REDACTED_HOSTNAME]"
    assert redacted_payload["mac_address"] == "[REDACTED_MAC]"
    assert "[REDACTED_USER]" in str(redacted_payload["path"])


def test_rule_registry_validation_reports_registered_rules() -> None:
    summary = rule_registry_summary()
    assert summary["rule_count"] > 0
    assert summary["validation_problem_count"] == 0
    assert validate_rule_registry() == []


def test_operational_health_report_includes_core_components(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("last_heartbeat", "2026-06-01T12:00:00+00:00")
    db.set_background_monitor_state("detector_last_run_timestamp", "2026-06-01T12:00:00+00:00")
    db.set_background_monitor_state("notification_status", "available via AppleScript")
    engine = OperationalHealthEngine(
        db,
        user_launch_agent=_FakeLaunchAgent(),
        system_launch_agent=_FakeLaunchAgent(),
        notification_manager=_FakeNotifier(),
        system_readiness=_FakeReadiness(),
        cve_radar_engine=_FakeRadar(),
        reports_dir=tmp_path / "reports",
        health_log_path=tmp_path / "operational_health.log",
    )
    report = engine.build_report()
    components = {check.component for check in report.checks}
    assert {"App", "Source Integrity", "SQLite", "Rule Registry", "System Monitor", "Notifier", "User LaunchAgent", "System LaunchDaemon", "Detector", "Apple Exposure Assessment", "Report Export"} <= components
    assert report.health_score > 0
    assert report.overall_status in {"healthy", "repair recommended", "degraded", "broken"}


def test_operational_health_component_permission_error_becomes_health_check(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    engine = OperationalHealthEngine(
        db,
        user_launch_agent=_FakeLaunchAgent(),
        system_launch_agent=_FakeLaunchAgent(),
        notification_manager=_FakeNotifier(),
        system_readiness=_PermissionDeniedReadiness(),
        cve_radar_engine=_FakeRadar(),
        reports_dir=tmp_path / "reports",
        health_log_path=tmp_path / "operational_health.log",
    )

    report = engine.build_report()
    monitor = next(check for check in report.checks if check.component == "System Monitor")

    assert monitor.status == "degraded"
    assert monitor.category == "permission_issue"
    assert "classicdatavault" in monitor.evidence
    assert report.overall_status in {"degraded", "broken"}


def test_operational_health_uses_application_integrity_root(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    app_root = tmp_path / "app-resources"
    seen: list[Path] = []

    class _FakeIntegrityStatus:
        status = "verified"
        result_code = "VALID"
        source_modified_files: list[str] = []
        missing_files: list[str] = []
        extra_files: list[str] = []
        generated_modified_files: list[str] = []
        recommended_action = ""
        reason = "ok"
        git_commit = "commit"
        build_id = "build"
        trust_state = "trusted"
        manifest_path = str(app_root / "mac_audit_agent" / "integrity" / "integrity_manifest.json")
        authority = {"checked_files": 1, "excluded_files": []}

        def to_dict(self) -> dict[str, object]:
            return {
                "status": self.status,
                "result_code": self.result_code,
                "trust_state": self.trust_state,
                "manifest_path": self.manifest_path,
                "source_modified_files": [],
                "missing_files": [],
                "extra_files": [],
                "authority": self.authority,
            }

    class _FakeAdapter:
        def __init__(self, root: Path | None = None) -> None:
            seen.append(Path(root or ""))

        def get_integrity_status_for_operational_health(self):
            return _FakeIntegrityStatus()

    monkeypatch.setattr("mac_audit_agent.operational_health.application_integrity_root", lambda: app_root)
    monkeypatch.setattr("mac_audit_agent.operational_health.IntegrityWrapperAdapter", _FakeAdapter)

    report = _health_engine(db, tmp_path).build_report()
    source = next(check for check in report.checks if check.component == "Source Integrity")

    assert source.status == "healthy"
    assert seen
    assert all(path == app_root for path in seen)


def _health_engine(db: AuditDatabase, tmp_path: Path) -> OperationalHealthEngine:
    return OperationalHealthEngine(
        db,
        user_launch_agent=_FakeLaunchAgent(),
        system_launch_agent=_FakeLaunchAgent(),
        notification_manager=_FakeNotifier(),
        system_readiness=_FakeReadiness(),
        cve_radar_engine=_FakeRadar(),
        reports_dir=tmp_path / "reports",
        health_log_path=tmp_path / "operational_health.log",
    )


def test_missing_source_integrity_manifest_is_degraded_not_broken(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    report = _health_engine(db, tmp_path).build_report()
    source = next(check for check in report.checks if check.component == "Source Integrity")

    assert source.status == "degraded"
    assert "No trusted integrity manifest" in source.summary


def test_detector_health_reads_active_system_monitor_database(tmp_path: Path, monkeypatch) -> None:
    settings_db = AuditDatabase(tmp_path / "settings.sqlite", tmp_path / "logs")
    system_path = tmp_path / "system.sqlite"
    system_db = AuditDatabase(system_path, tmp_path / "system-logs")
    system_db.set_background_monitor_state("detector_last_run_timestamp", "2026-07-17T20:00:00+00:00")
    system_db.set_background_monitor_state("detector_errors", "{}")
    system_db.close()
    monkeypatch.setattr("mac_audit_agent.operational_health.get_active_monitor_db_path", lambda _path: system_path)

    detector = _health_engine(settings_db, tmp_path)._detector_health()

    assert detector.status == "healthy"
    assert detector.evidence == "2026-07-17T20:00:00+00:00"


def test_draft_source_integrity_manifest_is_degraded_not_broken(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    record_source_integrity_baseline(db, root=root, trust_state="draft")

    report = _health_engine(db, tmp_path).build_report()
    source = next(check for check in report.checks if check.component == "Source Integrity")

    assert source.status == "degraded"
    assert "draft" in source.summary.lower()


def test_matching_source_integrity_manifest_is_healthy(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "monitor.log").write_text("first", encoding="utf-8")
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    record_source_integrity_baseline(db, root=root)

    (root / "logs" / "monitor.log").write_text("changed mutable log", encoding="utf-8")
    report = _health_engine(db, tmp_path).build_report()
    source = next(check for check in report.checks if check.component == "Source Integrity")

    assert source.status == "healthy"
    assert "match" in source.summary.lower()


def test_degraded_report_includes_issue_reason_fix_and_component_breakdown(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    report = OperationalHealthEngine(
        db,
        user_launch_agent=_FakeLaunchAgent(installed=False, loaded=False, running=False),
        system_launch_agent=_FakeLaunchAgent(),
        notification_manager=_FakeNotifier(),
        system_readiness=_FakeReadiness(),
        cve_radar_engine=_FakeRadar(),
        reports_dir=tmp_path / "reports",
        health_log_path=tmp_path / "operational_health.log",
    ).build_report()

    assert report.overall_status == "degraded"
    assert report.primary_cause is not None
    assert report.primary_cause.title
    assert report.primary_cause.description
    assert report.primary_cause.suggested_fix
    assert report.issues
    assert all(issue.description and issue.suggested_fix for issue in report.issues)
    assert any(component.component == "User LaunchAgent" and component.fix_label == "Repair Notifier" for component in report.components)
    assert "Degraded (" in report.display_status
    assert (tmp_path / "operational_health.log").exists()


def test_analyze_operational_health_ranks_all_root_causes_without_collapsing() -> None:
    analysis = analyze_operational_health(
        [
            HealthCheck("Notifier", "degraded", "User notifier unavailable.", "notification_status=unavailable", "Repair Notifier.", "notifier_failure", True),
            HealthCheck("Source Integrity", "critical", "Possible program modification or tampering detected.", "changed=1", "View Integrity Report.", "integrity_mismatch", False, False, True),
            HealthCheck("Settings System", "degraded", "Settings mismatch detected.", "runtime=settings drift", "Re-sync Settings.", "configuration", True),
        ]
    )

    assert len(analysis.issues) == 3
    assert analysis.primary_cause is not None
    assert analysis.primary_cause.risk_of_tampering is True
    assert analysis.root_cause_ranking[0]["severity"] == "critical"


def test_matching_disk_source_manifest_is_healthy_without_cached_baseline(tmp_path: Path) -> None:
    root = tmp_path / "project"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = create_integrity_manifest(root, source_type="source_tree")
    write_integrity_manifest(manifest, root / "msaa_integrity_manifest.json")
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")

    from mac_audit_agent import source_integrity

    original_project_root = source_integrity.project_root
    source_integrity.project_root = lambda: root
    try:
        report = _health_engine(db, tmp_path).build_report()
    finally:
        source_integrity.project_root = original_project_root
    source = next(check for check in report.checks if check.component == "Source Integrity")

    assert source.status == "healthy"
    assert "match" in source.summary.lower()
