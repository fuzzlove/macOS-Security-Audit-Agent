from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mac_audit_agent.quality.audit_models import AuditContext, AuditReport, CheckStatus, FunctionalCheck, ReadinessDecision
from mac_audit_agent.version import APP_VERSION, current_git_commit
from mac_audit_agent.launch_agent import project_root


@dataclass
class FunctionalCheckResult:
    check_id: str
    feature_area: str
    capability_name: str
    description: str
    expected_behavior: str
    actual_behavior: str
    status: str
    severity_if_failed: str
    evidence: dict[str, Any] = field(default_factory=dict)
    failure_stage: str = "unknown"
    root_cause_hint: str = ""
    suggested_fix: str = ""
    affected_files: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    timestamp: str = ""
    duration_ms: int = 0

    @classmethod
    def from_check(cls, check: FunctionalCheck) -> "FunctionalCheckResult":
        return cls(
            check_id=check.check_id,
            feature_area=check.feature_area,
            capability_name=check.name,
            description=check.description,
            expected_behavior=check.expected_result,
            actual_behavior=check.actual_result,
            status=check.status.lower(),
            severity_if_failed=check.severity_if_failed,
            evidence=check.evidence,
            failure_stage=check.failure_stage,
            root_cause_hint=check.root_cause_hint,
            suggested_fix=check.recommended_fix,
            affected_files=check.affected_files,
            artifacts=check.artifacts,
            timestamp=check.timestamp,
            duration_ms=check.duration_ms,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class PreUATAuditResult:
    audit_id: str
    started_at: str
    completed_at: str
    hostname: str
    app_version: str
    git_commit: str
    platform: str
    readiness_status: str
    blocker_count: int
    critical_count: int
    warning_count: int
    skipped_count: int
    passed_count: int
    checks: list[FunctionalCheckResult]

    @classmethod
    def from_report(cls, report: AuditReport) -> "PreUATAuditResult":
        counts = report.counts
        readiness = {
            "READY FOR USER TESTING": "ready",
            "READY WITH WARNINGS": "ready_with_warnings",
            "READY ONLY AFTER FIXES": "not_ready",
            "NOT READY FOR USER TESTING": "not_ready",
        }.get(report.readiness_decision, "audit_failed" if report.crashed else "not_ready")
        return cls(
            audit_id=report.run_id,
            started_at=report.started_at,
            completed_at=report.completed_at,
            hostname=report.hostname,
            app_version=APP_VERSION,
            git_commit=current_git_commit(project_root()),
            platform=__import__("platform").platform(),
            readiness_status=readiness,
            blocker_count=counts["BLOCKER"],
            critical_count=counts["FAIL"],
            warning_count=counts["WARN"],
            skipped_count=counts["SKIPPED"],
            passed_count=counts["PASS"],
            checks=[FunctionalCheckResult.from_check(check) for check in report.checks],
        )

    def to_dict(self) -> dict[str, Any]:
        data = self.__dict__.copy()
        data["checks"] = [check.to_dict() for check in self.checks]
        return data


__all__ = [
    "AuditContext",
    "AuditReport",
    "CheckStatus",
    "FunctionalCheck",
    "FunctionalCheckResult",
    "PreUATAuditResult",
    "ReadinessDecision",
]
