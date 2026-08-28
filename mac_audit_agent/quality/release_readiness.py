from __future__ import annotations

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.reliability import ReleaseReadinessEngine
from mac_audit_agent.storage import AuditDatabase


def run_release_audit(context: AuditContext) -> list[FunctionalCheck]:
    generated = FunctionalCheck("release.readiness_report_generated", "Release", "release readiness report generated", "Release readiness dashboard builds.", "critical", "smoke")
    public_gate = FunctionalCheck("release.public_distribution_gate", "Release", "public distribution gate", "All required public-distribution predicates pass with current evidence.", "blocker", "release_gate")
    try:
        report = ReleaseReadinessEngine(AuditDatabase(context.db_path)).build_report(run_expensive=False)
        payload = report.to_dict()
        release_status = str(payload.get("status", "")).lower()
        blocking_checks = [
            item for item in payload.get("checks", [])
            if str(item.get("status", "")).lower() in {"block", "fail", "broken"}
        ]
        evidence = {
            "release_readiness_report_generated": True,
            "release_status": release_status,
            "blocking_checks": blocking_checks[:10],
            "release_blocking_count": len(blocking_checks),
            "release_nonblocking_count": len(payload.get("remaining_non_blocking_checks", [])),
            "release_ready_for_public_distribution": release_status == "ready" and not blocking_checks,
            "score": payload.get("score", payload.get("readiness_score")),
            "readiness_score": payload.get("readiness_score", payload.get("score")),
            "status_reason": payload.get("status_reason", ""),
            "remaining_non_blocking_checks": payload.get("remaining_non_blocking_checks", []),
            "missing_release_evidence": payload.get("missing_release_evidence", []),
            "recommended_next_steps": payload.get("recommended_next_steps", []),
            "generated_at": payload.get("generated_at"),
        }
        failed = [item for item in payload.get("checks", []) if str(item.get("status", "")).lower() in {"fail", "broken"}]
        if failed or release_status == "blocked":
            return [
                generated.passed("Release readiness report generated successfully.", evidence | {"failed": failed[:10]}),
                public_gate.failed("Public distribution is blocked by current release evidence.", "Resolve the listed release checks and rerun the gate against the current tree and artifacts.", evidence),
            ]
        if release_status and release_status != "ready":
            return [generated.passed("Release readiness report generated successfully.", evidence), public_gate.failed("Public distribution requirements are incomplete.", "Complete current clean-install, test-matrix, integrity, and packaging evidence.", evidence)]
        return [generated.passed("Release readiness report generated.", evidence), public_gate.passed("Public distribution gate passed.", evidence)]
    except Exception as exc:
        generated.failure_stage = "unknown"
        return [generated.failed(str(exc), "Fix ReleaseReadinessEngine before UAT.", {"exception": type(exc).__name__})]


__all__ = ["run_release_audit"]
