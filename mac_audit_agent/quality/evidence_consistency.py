from __future__ import annotations

from mac_audit_agent.quality.audit_models import AuditReport, FunctionalCheck
from mac_audit_agent.quality.check_consistency import normalize_check_status


def scan_check_for_failed_evidence(check: FunctionalCheck) -> bool:
    evidence = check.evidence or {}
    if str(evidence.get("status", "")).lower() in {"failed", "error"}:
        return True
    if evidence.get("signature_valid") is False:
        return True
    if evidence.get("trust_state") in {"release_artifact_mismatch", "signature_invalid", "source_files_modified"}:
        return True
    return False


def fail_on_pass_with_failed_evidence(report: AuditReport) -> AuditReport:
    for check in report.checks:
        if check.status == "PASS" and scan_check_for_failed_evidence(check):
            normalize_check_status(check)
            if check.status == "PASS":
                check.status = "BLOCKER" if check.severity_if_failed == "blocker" else "FAIL"
    return report


__all__ = ["fail_on_pass_with_failed_evidence", "normalize_check_status", "scan_check_for_failed_evidence"]
