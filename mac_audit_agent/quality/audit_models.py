from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from mac_audit_agent.models import utc_now_iso


CheckStatus = Literal["PASS", "WARN", "FAIL", "SKIPPED", "BLOCKER"]
ReadinessDecision = Literal["READY FOR USER TESTING", "READY WITH WARNINGS", "READY ONLY AFTER FIXES", "NOT READY FOR USER TESTING"]
FAILURE_STAGES = {
    "ui_control_missing",
    "ui_control_disconnected",
    "settings_not_saved",
    "settings_not_loaded",
    "runtime_not_updated",
    "daemon_not_running",
    "notifier_not_running",
    "db_path_mismatch",
    "event_not_written",
    "event_not_consumed",
    "alert_policy_suppressed",
    "overlay_not_rendered",
    "scan_failed",
    "export_failed",
    "stale_data",
    "missing_dependency",
    "permission_issue",
    "unsupported_platform",
    "unknown",
}


@dataclass
class FunctionalCheck:
    check_id: str
    feature_area: str
    name: str
    description: str
    severity_if_failed: str = "medium"
    test_type: str = "smoke"
    command_or_callable: str = ""
    expected_result: str = ""
    actual_result: str = ""
    status: CheckStatus = "SKIPPED"
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_fix: str = ""
    failure_stage: str = "unknown"
    root_cause_hint: str = ""
    affected_files: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    duration_ms: int = 0
    timestamp: str = field(default_factory=utc_now_iso)
    callable_ref: Callable[..., "FunctionalCheck"] | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("callable_ref", None)
        return payload

    def passed(self, actual: str = "", evidence: dict[str, Any] | None = None) -> "FunctionalCheck":
        self.status = "PASS"
        self.actual_result = actual or self.expected_result or "verified"
        if evidence:
            self.evidence.update(evidence)
        self.timestamp = utc_now_iso()
        return self

    def warn(self, actual: str, recommended_fix: str, evidence: dict[str, Any] | None = None) -> "FunctionalCheck":
        self.status = "WARN"
        self.actual_result = actual
        self.recommended_fix = recommended_fix
        if evidence:
            self.evidence.update(evidence)
        self.timestamp = utc_now_iso()
        return self

    def failed(self, actual: str, recommended_fix: str, evidence: dict[str, Any] | None = None) -> "FunctionalCheck":
        self.status = "BLOCKER" if self.severity_if_failed == "blocker" else "FAIL"
        self.actual_result = actual
        self.recommended_fix = recommended_fix
        if self.failure_stage not in FAILURE_STAGES:
            self.failure_stage = "unknown"
        if evidence:
            self.evidence.update(evidence)
        self.timestamp = utc_now_iso()
        return self

    def skipped(self, actual: str, recommended_fix: str = "", evidence: dict[str, Any] | None = None) -> "FunctionalCheck":
        self.status = "SKIPPED"
        self.actual_result = actual
        self.recommended_fix = recommended_fix
        if evidence:
            self.evidence.update(evidence)
        self.timestamp = utc_now_iso()
        return self


@dataclass
class AuditReport:
    run_id: str
    hostname: str
    started_at: str
    completed_at: str = ""
    mode: str = "full"
    checks: list[FunctionalCheck] = field(default_factory=list)
    output_paths: dict[str, str] = field(default_factory=dict)
    crashed: bool = False
    crash_error: str = ""

    def add(self, check: FunctionalCheck) -> FunctionalCheck:
        self.checks.append(check)
        return check

    @property
    def counts(self) -> dict[str, int]:
        return {status: sum(1 for check in self.checks if check.status == status) for status in ["PASS", "WARN", "FAIL", "SKIPPED", "BLOCKER"]}

    @property
    def readiness_decision(self) -> ReadinessDecision:
        counts = self.counts
        if counts["BLOCKER"]:
            return "NOT READY FOR USER TESTING"
        if counts["FAIL"]:
            return "READY ONLY AFTER FIXES"
        if counts["WARN"] or counts["SKIPPED"]:
            return "READY WITH WARNINGS"
        return "READY FOR USER TESTING"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "hostname": self.hostname,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "mode": self.mode,
            "readiness_decision": self.readiness_decision,
            "counts": self.counts,
            "crashed": self.crashed,
            "crash_error": self.crash_error,
            "output_paths": self.output_paths,
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass
class AuditContext:
    db_path: Path
    output_dir: Path
    mode: str = "full"
    allow_alert_render: bool = False
    allow_exports: bool = True
    allow_safe_scan: bool = False
    fail_on_blocker: bool = False
