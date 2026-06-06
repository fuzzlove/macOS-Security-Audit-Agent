from __future__ import annotations

from pathlib import Path

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.operational_health import OperationalHealthEngine
from mac_audit_agent.privacy import redact_text, redact_structure
from mac_audit_agent.rules import rule_registry_summary, validate_rule_registry
from mac_audit_agent.storage import AuditDatabase


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
    )
    report = engine.build_report()
    components = {check.component for check in report.checks}
    assert {"App", "Source Integrity", "SQLite", "Rule Registry", "System Monitor", "Notifier", "User LaunchAgent", "System LaunchDaemon", "Detector", "Apple Security Forecast", "Report Export"} <= components
    assert report.health_score > 0
    assert report.overall_status in {"healthy", "repair recommended", "degraded", "broken"}
