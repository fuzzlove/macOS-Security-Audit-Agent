from __future__ import annotations

from dataclasses import dataclass, field
import os
import socket
from pathlib import Path
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
        return _redact_value(self.__dict__.copy())


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
    manual_testing_readiness: str
    release_readiness: str
    ready_for_headless_testing: bool
    ready_for_interactive_uat: bool
    ready_for_public_release: bool
    manual_testing_checklist: dict[str, Any]
    blocker_count: int
    critical_count: int
    warning_count: int
    skipped_count: int
    passed_count: int
    degraded_count: int
    not_verified_count: int
    harness_error_count: int
    crashed: bool
    crash_error: str
    checks: list[FunctionalCheckResult]

    @classmethod
    def from_report(cls, report: AuditReport) -> "PreUATAuditResult":
        counts = report.counts
        checks_by_id = {check.check_id: check for check in report.checks}
        manual_checklist = _manual_testing_checklist(report)
        manual_ready = _manual_testing_readiness(report, manual_checklist)
        release_ready = _release_readiness(checks_by_id)
        headless_ready = not report.crashed and counts["HARNESS_ERROR"] == 0 and counts["BLOCKER"] == 0 and counts["FAIL"] == 0
        interactive_ready = manual_ready == "ready"
        public_ready = release_ready == "ready" and interactive_ready
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
            hostname="<redacted-host>",
            app_version=APP_VERSION,
            git_commit=current_git_commit(project_root()),
            platform=__import__("platform").platform(),
            readiness_status=readiness,
            manual_testing_readiness=manual_ready,
            release_readiness=release_ready,
            ready_for_headless_testing=headless_ready,
            ready_for_interactive_uat=interactive_ready,
            ready_for_public_release=public_ready,
            manual_testing_checklist=manual_checklist,
            blocker_count=counts["BLOCKER"],
            critical_count=counts["FAIL"],
            warning_count=counts["WARN"],
            skipped_count=counts["SKIPPED"],
            passed_count=counts["PASS"],
            degraded_count=counts["DEGRADED"],
            not_verified_count=counts["NOT_VERIFIED"],
            harness_error_count=counts["HARNESS_ERROR"],
            crashed=report.crashed,
            crash_error=report.crash_error,
            checks=[FunctionalCheckResult.from_check(check) for check in report.checks],
        )

    def to_dict(self) -> dict[str, Any]:
        data = self.__dict__.copy()
        data["checks"] = [check.to_dict() for check in self.checks]
        return _redact_value(data)


def _redact_value(value: Any, key: str = "") -> Any:
    secret_markers = ("token", "secret", "password", "credential", "api_key", "ssh_auth_sock")
    if any(marker in key.lower() for marker in secret_markers):
        return "<redacted>"
    if "pid" in key.lower() and isinstance(value, (int, str)) and str(value).strip():
        return "<PID>"
    if isinstance(value, dict):
        return {str(item_key): _redact_value(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        limit = len(value) if key == "checks" else 50
        items = [_redact_value(item, key) for item in value[:limit]]
        if len(value) > limit:
            items.append({"truncated": True, "omitted_items": len(value) - limit})
        return items
    if isinstance(value, tuple):
        return [_redact_value(item, key) for item in value]
    if isinstance(value, str):
        result = value
        home = str(Path.home())
        root = str(project_root())
        hostname = socket.gethostname()
        user = Path.home().name
        system_support = "/Library/Application Support/MacAuditAgent"
        app_support = str(Path.home() / "Library" / "Application Support" / "MacAuditAgent")
        if root:
            result = result.replace(root, "<PROJECT_ROOT>")
        result = result.replace(app_support, "<APP_SUPPORT>")
        result = result.replace(system_support, "<SYSTEM_APP_SUPPORT>")
        if home and home != "/":
            result = result.replace(home, "<HOME>")
        if user:
            result = result.replace(f"/Users/{user}", "<HOME>")
        if hostname:
            result = result.replace(hostname, "<HOST>")
        ssh_socket = os.environ.get("SSH_AUTH_SOCK", "")
        if ssh_socket:
            result = result.replace(ssh_socket, "<redacted>")
        return result if len(result) <= 4000 else result[:4000] + "\n<truncated>"
    return value


def _manual_testing_checklist(report: AuditReport) -> dict[str, Any]:
    checks_by_id = {check.check_id: check for check in report.checks}

    def ok(check_id: str) -> bool:
        check = checks_by_id.get(check_id)
        return bool(check and check.status == "PASS")

    items = {
        "user_notifier_running": ok("daemon.notifier_heartbeat"),
        "system_daemon_heartbeat_fresh": ok("daemon.heartbeat"),
        "active_db_alignment_passed": ok("daemon.notifier_heartbeat"),
        "safe_scan_fresh": ok("scan.safe_scan"),
        "apple_exposure_checked": ok("scan.apple_exposure"),
        "persistence_intelligence_available": ok("persistence.workflow"),
        "network_intelligence_available": all(ok(check_id) for check_id in ["network_intelligence.collectors", "network_intelligence.storage_events", "network_intelligence.reports"]),
        "physical_devices_artifacts_present": ok("scan.physical_devices"),
        "exports_pass": all(ok(check_id) for check_id in ["exports.html", "exports.json", "exports.word", "exports.excel"]),
        "interactive_bottom_right_alert_verified": ok("alert.bottom_right_rendering"),
        "no_blockers": report.counts["BLOCKER"] == 0,
        "no_failures": report.counts["FAIL"] == 0,
    }
    missing = [name for name, passed in items.items() if not passed]
    status = "ready" if not missing else ("not_ready" if report.counts["BLOCKER"] or report.counts["FAIL"] else "ready_with_warnings")
    return {
        "status": status,
        "items": items,
        "missing_items": missing,
        "recommended_next_steps": _manual_next_steps(missing),
    }


def _manual_next_steps(missing: list[str]) -> list[str]:
    labels = {
        "user_notifier_running": "Run Repair User Alert Agent.",
        "system_daemon_heartbeat_fresh": "Restart or repair the monitor daemon.",
        "active_db_alignment_passed": "Repair DB path alignment for daemon, notifier, event, and alert trace paths.",
        "safe_scan_fresh": "Run Safe Scan.",
        "apple_exposure_checked": "Refresh Apple Exposure Assessment.",
        "persistence_intelligence_available": "Run Persistence Intelligence.",
        "network_intelligence_available": "Run Network Intelligence.",
        "physical_devices_artifacts_present": "Run Safe Scan and verify physical device artifacts.",
        "exports_pass": "Run export checks for HTML, JSON, Word, and Excel.",
        "interactive_bottom_right_alert_verified": "Run python3 -m mac_audit_agent.quality.pre_uat_audit --alerts --interactive.",
        "no_blockers": "Resolve blocker checks.",
        "no_failures": "Resolve failed checks.",
    }
    return [labels[item] for item in missing if item in labels]


def _manual_testing_readiness(report: AuditReport, checklist: dict[str, Any]) -> str:
    if report.counts["BLOCKER"] or report.counts["FAIL"] or report.counts["NOT_VERIFIED"] or report.counts["HARNESS_ERROR"]:
        return "not_ready"
    return "ready" if checklist.get("status") == "ready" else "not_ready"


def _release_readiness(checks_by_id: dict[str, FunctionalCheck]) -> str:
    check = checks_by_id.get("release.public_distribution_gate")
    if not check:
        return "not_evaluated"
    return "ready" if check.status == "PASS" else "blocked"


__all__ = [
    "AuditContext",
    "AuditReport",
    "CheckStatus",
    "FunctionalCheck",
    "FunctionalCheckResult",
    "PreUATAuditResult",
    "ReadinessDecision",
]
