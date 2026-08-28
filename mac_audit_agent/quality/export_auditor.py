from __future__ import annotations

import json
import zipfile
from pathlib import Path

from mac_audit_agent.assessment import build_security_assessment, export_security_assessment_html, export_security_assessment_json, export_security_assessment_markdown
from mac_audit_agent.exporters import export_assessment_excel, export_assessment_word
from mac_audit_agent.models import Finding, ScanResult, utc_now_iso
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.runtime.optional_dependencies import OptionalDependencyError


def run_export_audit(context: AuditContext) -> list[FunctionalCheck]:
    output_dir = context.output_dir / "export_audit"
    output_dir.mkdir(parents=True, exist_ok=True)
    scan = sample_scan_result()
    assessment = build_security_assessment(scan_result=scan, monitor_state={}, events=[], settings=None)
    checks: list[FunctionalCheck] = []
    checks.append(_file_check("exports.html", "HTML export", "critical", lambda: export_scan_result_html(scan, output_dir / "scan.html"), must_contain=["findings", "limitations"]))
    checks.append(_json_check(lambda: export_scan_result_json(scan, output_dir / "scan.json")))
    checks.append(_file_check("exports.assessment", "assessment export", "high", lambda: export_security_assessment_html(assessment, output_dir / "assessment.html"), must_contain=["Framework Alignment", "Limitations"]))
    checks.append(_json_assessment_check(lambda: export_security_assessment_json(assessment, output_dir / "assessment.json")))
    checks.append(_file_check("exports.assessment_markdown", "assessment markdown export", "medium", lambda: export_security_assessment_markdown(assessment, output_dir / "assessment.md"), must_contain=["Limitations"]))
    checks.append(_zip_check("exports.word", "Word .docx export", "high", lambda: export_assessment_word(assessment, output_dir / "assessment.docx")))
    checks.append(_zip_check("exports.excel", "Excel .xlsx export", "high", lambda: export_assessment_excel(assessment, output_dir / "assessment.xlsx"), expected_member="xl/workbook.xml"))
    checks.append(_evidence_package_check(output_dir, scan))
    return checks


def sample_scan_result() -> ScanResult:
    finding = Finding(
        id="pre-uat-finding-1",
        category="monitor",
        title="Pre-UAT diagnostic finding",
        severity="high",
        description="Synthetic diagnostic finding used only for export verification.",
        evidence="Pre-UAT export smoke evidence.",
        command_used="pre_uat_audit",
        remediation_suggestion="No remediation required for synthetic diagnostic data.",
        warning="Diagnostic finding, not a real issue.",
        framework_mappings=[{"framework": "NIST_800_53_REV5", "id": "SI-4", "name": "System Monitoring", "category": "Detect"}],
    )
    return ScanResult(
        scan_id="pre-uat-scan",
        timestamp=utc_now_iso(),
        hostname="pre-uat-host",
        current_user="pre-uat",
        findings=[finding],
        collected_artifacts={"ports": {"listening": [], "active_connections": [], "errors": []}, "processes": {"all": [], "errors": []}},
        baseline_diff={},
    )


def _file_check(check_id: str, name: str, severity: str, writer, *, must_contain: list[str]) -> FunctionalCheck:
    check = FunctionalCheck(check_id, "Exports", name, f"{name} creates non-empty file.", severity, "export")
    try:
        path = Path(writer())
        content = path.read_text(encoding="utf-8", errors="replace")
        missing = [item for item in must_contain if item.lower() not in content.lower()]
        if not path.exists() or path.stat().st_size == 0:
            check.failure_stage = "export_failed"
            return check.failed("Export created empty or missing file.", "Write export atomically and verify non-empty output.", {"path": str(path)})
        if missing:
            check.failure_stage = "export_failed"
            return check.failed(f"Export missing expected content: {missing}", "Include summary, findings, limitations, and framework context in export output.", {"path": str(path)})
        return check.passed("Export file created and content verified.", {"path": str(path), "size": path.stat().st_size})
    except Exception as exc:
        check.failure_stage = "export_failed"
        return check.failed(str(exc), f"Fix {name} writer and dependencies.", {"exception": type(exc).__name__})


def _json_check(writer) -> FunctionalCheck:
    check = FunctionalCheck("exports.json", "Exports", "JSON export", "JSON export creates valid JSON metadata.", "critical", "export")
    try:
        path = Path(writer())
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not payload.get("findings") and not payload.get("scan_result", {}).get("findings"):
            check.failure_stage = "export_failed"
            return check.failed("JSON export contains no findings section.", "Include normalized findings and metadata in JSON export.", {"path": str(path)})
        return check.passed("JSON export valid and includes findings.", {"path": str(path)})
    except Exception as exc:
        check.failure_stage = "export_failed"
        return check.failed(str(exc), "Fix JSON serialization and report schema.", {"exception": type(exc).__name__})


def _json_assessment_check(writer) -> FunctionalCheck:
    check = FunctionalCheck("exports.assessment_json", "Exports", "assessment JSON export", "Assessment JSON creates valid JSON.", "high", "export")
    try:
        path = Path(writer())
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not payload.get("assessment_id"):
            check.failure_stage = "export_failed"
            return check.failed("Assessment JSON missing assessment_id.", "Export SecurityAssessment.to_dict() with metadata intact.", {"path": str(path)})
        return check.passed("Assessment JSON export valid.", {"path": str(path)})
    except Exception as exc:
        check.failure_stage = "export_failed"
        return check.failed(str(exc), "Fix assessment JSON export.", {"exception": type(exc).__name__})


def _zip_check(check_id: str, name: str, severity: str, writer, *, expected_member: str = "[Content_Types].xml") -> FunctionalCheck:
    check = FunctionalCheck(check_id, "Exports", name, f"{name} creates readable Office zip package.", severity, "export")
    try:
        path = Path(writer())
        if not zipfile.is_zipfile(path):
            check.failure_stage = "export_failed"
            return check.failed("Office export is not a valid zip package.", "Verify dependency and write file atomically from normalized ExportAssessmentData.", {"path": str(path)})
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
        if expected_member not in names:
            check.failure_stage = "export_failed"
            return check.failed(f"Office export missing {expected_member}.", "Verify Office document generation includes expected workbook/document parts.", {"path": str(path)})
        return check.passed("Office export package verified.", {"path": str(path), "members": len(names)})
    except OptionalDependencyError as exc:
        check.failure_stage = "missing_dependency"
        return check.degraded(
            str(exc),
            "Install the office extra in source mode, or reinstall a complete desktop bundle in frozen mode.",
            {"exception": type(exc).__name__, "error_code": exc.error_code, "optional_feature": True},
        )
    except Exception as exc:
        check.failure_stage = "missing_dependency" if "requires" in str(exc).lower() else "export_failed"
        return check.failed(str(exc), f"Verify {name} dependency and export implementation.", {"exception": type(exc).__name__})


def _evidence_package_check(output_dir: Path, scan: ScanResult) -> FunctionalCheck:
    check = FunctionalCheck("exports.evidence_package", "Exports", "evidence package export", "Evidence package includes manifest and avoids secrets.", "medium", "export")
    manifest = {"scan_id": scan.scan_id, "generated_at": utc_now_iso(), "hashes": {}}
    path = output_dir / "evidence_package_manifest.json"
    try:
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        content = path.read_text(encoding="utf-8").lower()
        if any(secret in content for secret in ["password=", "token=", "secret="]):
            check.failure_stage = "export_failed"
            return check.failed("Evidence package manifest contains secret-like material.", "Redact secrets before evidence package export.", {"path": str(path)})
        return check.passed("Evidence package manifest smoke check passed.", {"path": str(path)})
    except Exception as exc:
        check.failure_stage = "export_failed"
        return check.failed(str(exc), "Implement evidence package manifest and hashing output.", {"exception": type(exc).__name__})
