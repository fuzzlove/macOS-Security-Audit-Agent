from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.quality.audit_models import AuditContext, AuditReport, FunctionalCheck
from mac_audit_agent.quality.audit_reporter import write_reports
from mac_audit_agent.quality.check_models import FunctionalCheckResult, PreUATAuditResult
from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.quality.ui_control_auditor import static_ui_control_audit
from mac_audit_agent.quality.ui_control_auditor import write_ui_control_audit
from mac_audit_agent.quality.release_integrity_auditor import run_release_integrity_audit
from mac_audit_agent.ui.button_layout_auditor import write_button_layout_audit
from mac_audit_agent.quality.daemon_auditor import run_daemon_audit
from mac_audit_agent.quality.export_auditor import run_export_audit
from mac_audit_agent.quality.scan_auditor import _apple_exposure_check
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.monitor_settings import load_settings, save_settings


def test_pre_uat_registry_loads() -> None:
    registry = build_registry()
    assert registry
    assert any(check.check_id == "alert.delivery_trace" for check in registry)


def test_check_result_serializes_with_suggested_fix() -> None:
    check = FunctionalCheck("x", "Core", "Example", "desc", "blocker")
    check.failure_stage = "notifier_not_running"
    check.failed("broken", "repair it", {"k": "v"})
    result = FunctionalCheckResult.from_check(check).to_dict()
    assert result["status"] == "blocker"
    assert result["suggested_fix"] == "repair it"
    assert result["failure_stage"] == "notifier_not_running"


def test_blocker_causes_not_ready() -> None:
    report = AuditReport("audit-1", "host", "2026-01-01T00:00:00+00:00")
    report.add(FunctionalCheck("x", "Core", "Example", "desc", "blocker").failed("broken", "repair"))
    canonical = PreUATAuditResult.from_report(report)
    assert report.readiness_decision == "NOT READY FOR USER TESTING"
    assert canonical.readiness_status == "not_ready"


def test_warning_does_not_block_readiness() -> None:
    report = AuditReport("audit-1", "host", "2026-01-01T00:00:00+00:00")
    report.add(FunctionalCheck("x", "Core", "Example", "desc").warn("warning", "review"))
    assert report.readiness_decision == "READY WITH WARNINGS"


def test_audit_report_generates_html_and_json(tmp_path: Path) -> None:
    report = AuditReport("audit-1", "host", "2026-01-01T00:00:00+00:00")
    report.completed_at = "2026-01-01T00:00:01+00:00"
    report.add(FunctionalCheck("x", "Core", "Example", "desc").passed("ok"))
    paths = write_reports(report, tmp_path)
    assert Path(paths["html"]).exists()
    payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert payload["audit_id"] == "audit-1"


def test_missing_notifier_detected_when_alerts_enabled(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.notification.bottom_right_alerts = True
    settings.user_notifier.enabled = True
    save_settings(db, settings)
    checks = run_daemon_audit(AuditContext(db.path, tmp_path))
    assert any(check.status == "BLOCKER" and "notifier" in check.name.lower() for check in checks)


def test_export_audit_detects_outputs(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    checks = run_export_audit(AuditContext(db.path, tmp_path))
    assert any(check.check_id == "exports.json" and check.status == "PASS" for check in checks)
    assert all(check.status in {"PASS", "DEGRADED"} for check in checks)
    assert all(check.recommended_fix or check.status == "PASS" for check in checks)


def test_ui_audit_detects_disconnected_button() -> None:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as directory:
        path = Path(directory) / "ui.py"
        path.write_text("self.dead_button = QPushButton('Dead Button')\n", encoding="utf-8")
        records = static_ui_control_audit([path])
    assert any(record["label"] == "Dead Button" and record["status"] == "FAIL" for record in records)


def test_apple_exposure_freshness_is_evidence_based(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    check = _apple_exposure_check(AuditContext(db.path, tmp_path))
    assert check.status in {"PASS", "WARN"}
    if check.status == "WARN":
        assert check.recommended_fix
    else:
        assert any(check.evidence.values())


def test_failed_checks_require_suggested_fix() -> None:
    report = AuditReport("audit-1", "host", "2026-01-01T00:00:00+00:00")
    report.add(FunctionalCheck("x", "Core", "Example", "desc", "blocker").failed("broken", "concrete fix"))
    assert all(check.recommended_fix for check in report.checks if check.status in {"FAIL", "BLOCKER", "WARN"})


def test_generated_ui_audit_reports_default_outside_docs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    ui_report = write_ui_control_audit([])
    button_report = write_button_layout_audit([])
    assert ui_report.as_posix() == "reports/pre_uat/ui_audits/PRE_UAT_UI_CONTROL_AUDIT.md"
    assert button_report.as_posix() == "reports/pre_uat/ui_audits/PRE_UAT_BUTTON_LAYOUT_AUDIT.md"


def test_integrity_pre_uat_checks_do_not_pass_with_failed_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mac_audit_agent").mkdir()
    checks = run_release_integrity_audit(AuditContext(tmp_path / "audit.sqlite", tmp_path))

    for check in checks:
        if check.status == "PASS":
            assert check.evidence.get("status") != "failed"

    release_file_check = next(check for check in checks if check.check_id == "integrity.files_match_manifest")
    assert release_file_check.status == "SKIPPED"
    assert release_file_check.evidence["status"] == "non_applicable_for_policy"


def test_manifest_path_consistency_blocks_legacy_only_manifest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    legacy = tmp_path / "mac_audit_agent" / "security" / "integrity_manifest.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")

    checks = run_release_integrity_audit(AuditContext(tmp_path / "audit.sqlite", tmp_path))
    consistency = next(check for check in checks if check.check_id == "integrity.manifest_path_consistency")

    assert consistency.status == "BLOCKER"
    assert consistency.evidence["trust_state"] == "manifest_path_divergence"
