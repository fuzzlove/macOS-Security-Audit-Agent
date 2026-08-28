from __future__ import annotations

from mac_audit_agent.quality.audit_models import FunctionalCheck


FAILED_EVIDENCE_STATUSES = {"fail", "failed", "error", "blocker", "harness_error"}
NON_APPLICABLE_EVIDENCE_STATUSES = {"non_applicable_for_policy", "not_applicable", "skipped"}

# Only evidence declared by the check itself may change its status. Shared
# diagnostic payloads often contain failures for other predicates (for
# example, a valid signature alongside changed source files).
REQUIRED_TRUE_FIELDS: dict[str, tuple[str, ...]] = {
    "daemon.user_launch_agent": ("healthy_for_selected_mode",),
    "alert.delivery_trace": ("event_persisted", "published", "notifier_received"),
    "settings.user_alert_agent_deliverability": ("deliverable",),
    "integrity.policy_resolved": ("policy_resolved",),
    "integrity.canonical_manifest_exists": ("manifest_exists",),
    "integrity.source_signature_valid": ("signature_valid",),
    "integrity.source_files_match_manifest": ("files_match",),
    "integrity.manifest_path_consistency": ("path_consistent",),
    "integrity.developer_machine_identity_exists": ("identity_exists",),
    "integrity.developer_machine_signature_valid": ("signature_valid",),
    "integrity.signing_machine_authorized": ("signer_authorized",),
    "integrity.integrity_cli_headless_safe": ("headless_safe",),
}


def normalize_check_status(check: FunctionalCheck) -> FunctionalCheck:
    evidence_status = str(check.evidence.get("status", "") or check.evidence.get("evidence_status", "")).lower()
    if check.status == "PASS" and evidence_status in FAILED_EVIDENCE_STATUSES:
        check.status = "BLOCKER" if check.severity_if_failed == "blocker" else "FAIL"
        check.actual_result = check.actual_result or "Check evidence indicates failure."
        check.recommended_fix = check.recommended_fix or "Repair the failed evidence source or mark the check non-applicable for the current policy."
        check.failure_stage = check.failure_stage if check.failure_stage != "unknown" else "release_blocked"
    if check.status == "PASS" and evidence_status in NON_APPLICABLE_EVIDENCE_STATUSES:
        check.status = "PASS" if check.evidence.get("safe_skip_expected") is True else "SKIPPED"
        check.actual_result = check.actual_result or "non_applicable_for_policy"
    contradictions = _contract_contradictions(check)
    if check.status == "PASS" and contradictions:
        check.status = "BLOCKER" if check.severity_if_failed == "blocker" else "FAIL"
        check.actual_result = "Contradictory evidence prevents PASS: " + "; ".join(contradictions)
        check.recommended_fix = check.recommended_fix or "Correct the underlying deployment or evidence and rerun this check."
        check.failure_stage = "release_blocked" if check.failure_stage == "unknown" else check.failure_stage
    return check


def _contract_contradictions(check: FunctionalCheck) -> list[str]:
    value = check.evidence
    problems: list[str] = []
    for field in REQUIRED_TRUE_FIELDS.get(check.check_id, ()):
        if value.get(field) is not True:
            problems.append(f"evidence.{field}={value.get(field)!r}")
    if value.get("expired") is True or value.get("evidence_expired") is True:
        problems.append("evidence is expired")
    return problems


__all__ = ["normalize_check_status"]
