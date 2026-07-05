from __future__ import annotations

from pathlib import Path

from mac_audit_agent.operational_health import HealthCheck, OperationalHealthReport
from mac_audit_agent.repair import OperationalRepairEngine, RepairAction
from mac_audit_agent.storage import AuditDatabase


class FakeHealthEngine:
    def __init__(self, report: OperationalHealthReport) -> None:
        self.report = report

    def build_report(self) -> OperationalHealthReport:
        return self.report


class FakeNotifierInstaller:
    def __init__(self, status) -> None:
        self.status = status
        self.repaired = False

    def repair_user_notifier(self):
        self.repaired = True
        return self.status


class FakeNotifierStatus:
    install_status = "loaded"
    last_error = ""

    def to_dict(self):
        return {"install_status": self.install_status, "loaded": True}


def _report(*checks: HealthCheck) -> OperationalHealthReport:
    return OperationalHealthReport(
        generated_at="2026-06-29T00:00:00+00:00",
        overall_status="broken",
        health_score=10,
        checks=list(checks),
        details={},
    )


def test_repair_action_serializes_and_safe_flag() -> None:
    action = RepairAction.create("Repair Logs", "Logs", "missing", "create dirs")
    payload = action.to_dict()
    assert payload["title"] == "Repair Logs"
    assert action.safe_to_run_automatically is True
    destructive = RepairAction.create("Delete DB", "Database", "corrupt", "delete", destructive=True)
    assert destructive.safe_to_run_automatically is False


def test_missing_notifier_creates_repair_action(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    engine = OperationalRepairEngine(
        db,
        health_engine=FakeHealthEngine(_report(HealthCheck("Notifier", "broken", "User notifier missing.", "", "Repair notifier."))),
        notifier_installer=FakeNotifierInstaller(FakeNotifierStatus()),
        log_path=tmp_path / "repair.log",
    )
    plan = engine.build_plan()
    assert any(action.component == "User Notifier" for action in plan.actions)
    assert all(not action.destructive for action in plan.actions)


def test_system_daemon_repair_requires_admin_and_not_run_silently(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    engine = OperationalRepairEngine(
        db,
        health_engine=FakeHealthEngine(_report(HealthCheck("System LaunchDaemon", "broken", "unloaded", "", "Repair daemon."))),
        log_path=tmp_path / "repair.log",
    )
    plan = engine.build_plan()
    action = next(item for item in plan.actions if item.component == "System LaunchDaemon")
    assert action.requires_admin is True
    result = engine.run_safe_repairs(plan)
    assert result.actions[0].status == "skipped"
    assert "administrator approval" in result.actions[0].error


def test_database_repair_runs_schema_without_deleting_events(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("preserve_me", "1")
    engine = OperationalRepairEngine(
        db,
        health_engine=FakeHealthEngine(_report(HealthCheck("SQLite", "degraded", "Tables missing", "", "Run migration."))),
        log_path=tmp_path / "repair.log",
    )
    result = engine.run_safe_repairs(engine.build_plan())
    assert result.actions[0].status == "succeeded"
    assert db.get_background_monitor_state("preserve_me", "") == "1"


def test_repair_history_logged(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    engine = OperationalRepairEngine(
        db,
        health_engine=FakeHealthEngine(_report(HealthCheck("SQLite", "degraded", "Tables missing", "", "Run migration."))),
        log_path=tmp_path / "repair.log",
    )
    engine.run_safe_repairs(engine.build_plan())
    rows = db.conn.execute("SELECT * FROM repair_history").fetchall()
    assert rows
    assert engine.log_path.exists()


def test_tamper_issue_does_not_auto_repair(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    report = _report(HealthCheck("Source Integrity", "critical", "Possible program modification or tampering detected.", "changed=1", "View evidence.", "integrity_mismatch", False, False, True))
    payload = report.to_dict()
    payload["issues"] = [
        {
            "issue_id": "source_integrity_critical",
            "component": "Source Integrity",
            "severity": "critical",
            "category": "integrity_mismatch",
            "title": "Integrity Verification Mismatch",
            "description": "Possible program modification or tampering detected.",
            "impact": "CRITICAL",
            "evidence": ["changed=1"],
            "suggested_fix": ["View Integrity Report", "Export Evidence Snapshot", "Reinstall From Trusted Source"],
            "auto_fixable": False,
            "requires_admin": False,
            "risk_of_tampering": True,
        }
    ]
    engine = OperationalRepairEngine(db, health_engine=FakeHealthEngine(report), log_path=tmp_path / "repair.log")

    plan = engine.build_plan(payload)
    assert plan.actions[0].title == "Do Not Auto-Fix"
    assert plan.actions[0].safe_to_run_automatically is False
    result = engine.run_safe_repairs(plan)
    assert result.actions[0].status == "skipped"
