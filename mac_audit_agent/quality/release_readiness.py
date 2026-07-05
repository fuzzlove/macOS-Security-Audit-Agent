from __future__ import annotations

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.reliability import ReleaseReadinessEngine
from mac_audit_agent.storage import AuditDatabase


def run_release_audit(context: AuditContext) -> list[FunctionalCheck]:
    check = FunctionalCheck("release.readiness", "Release", "release readiness", "Release readiness dashboard builds.", "critical", "smoke")
    try:
        report = ReleaseReadinessEngine(AuditDatabase(context.db_path)).build_report(run_expensive=False)
        payload = report.to_dict()
        failed = [item for item in payload.get("checks", []) if str(item.get("status", "")).lower() in {"fail", "broken"}]
        if failed:
            check.failure_stage = "unknown"
            return [check.failed("Release readiness reported failed checks.", "Fix release readiness failures before UAT.", {"failed": failed[:10]})]
        return [check.passed("Release readiness report generated.", payload)]
    except Exception as exc:
        check.failure_stage = "unknown"
        return [check.failed(str(exc), "Fix ReleaseReadinessEngine before UAT.", {"exception": type(exc).__name__})]


__all__ = ["run_release_audit"]
