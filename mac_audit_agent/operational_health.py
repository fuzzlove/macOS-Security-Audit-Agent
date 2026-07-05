from __future__ import annotations

import os
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mac_audit_agent.cve_radar import CveRadarEngine
from mac_audit_agent.launch_agent import LaunchAgentManager
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.rules import rule_registry_summary
from mac_audit_agent.source_integrity import verify_source_integrity
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness
from mac_audit_agent.version import APP_VERSION, current_git_commit


OperationalHealthState = Literal["healthy", "degraded", "broken", "critical", "unknown"]
OperationalHealthIssueCategory = Literal[
    "configuration",
    "runtime_failure",
    "missing_component",
    "integrity_mismatch",
    "permission_issue",
    "daemon_failure",
    "notifier_failure",
    "database_issue",
    "alert_pipeline_issue",
]

STATUS_ORDER = {
    "healthy": 6,
    "disabled_by_settings": 6,
    "unsupported": 6,
    "repair recommended": 4,
    "unavailable": 3,
    "unknown": 2,
    "degraded": 2,
    "broken": 1,
    "critical": 0,
}

INTEGRITY_HEALTH_BY_STATUS = {
    "verified": "healthy",
    "verified_with_warnings": "healthy",
    "unknown": "degraded",
    "draft": "degraded",
    "stale": "degraded",
    "incompatible_manifest": "degraded",
    "expired": "degraded",
    "revoked": "degraded",
    "partial": "degraded",
    "failed": "degraded",
    "modified": "broken",
}

INTEGRITY_SUMMARY_BY_STATUS = {
    "verified": "Python source hashes match the trusted manifest.",
    "verified_with_warnings": "Python source hashes match the trusted manifest with non-critical warnings.",
    "unknown": "No trusted integrity manifest is available.",
    "draft": "Only a draft hash manifest exists.",
    "stale": "Trusted integrity manifest was generated for a different MSAA build.",
    "incompatible_manifest": "Selected integrity manifest does not apply to this install mode.",
    "expired": "Integrity manifest is expired.",
    "revoked": "Integrity manifest is revoked.",
    "partial": "Some optional integrity checks could not complete.",
    "failed": "Integrity verifier failed with an exact error.",
    "modified": "Trusted integrity manifest mismatch detected.",
}


@dataclass(frozen=True)
class HealthCheck:
    component: str
    status: str
    summary: str
    evidence: str = ""
    next_step: str = ""
    category: OperationalHealthIssueCategory | str = "runtime_failure"
    auto_fixable: bool = False
    requires_admin: bool = False
    risk_of_tampering: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationalHealthIssue:
    issue_id: str
    component: str
    severity: OperationalHealthState
    category: OperationalHealthIssueCategory | str
    title: str
    description: str
    impact: str
    evidence: list[str] = field(default_factory=list)
    suggested_fix: list[str] = field(default_factory=list)
    auto_fixable: bool = False
    requires_admin: bool = False
    risk_of_tampering: bool = False
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationalComponentHealth:
    component: str
    status: str
    status_label: str
    reason: str
    last_check_timestamp: str
    fix_label: str = ""
    auto_fixable: bool = False
    requires_admin: bool = False
    risk_of_tampering: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationalHealthAnalysis:
    issues: list[OperationalHealthIssue]
    root_cause_ranking: list[dict[str, Any]]
    primary_cause: OperationalHealthIssue | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [issue.to_dict() for issue in self.issues],
            "root_cause_ranking": self.root_cause_ranking,
            "primary_cause": self.primary_cause.to_dict() if self.primary_cause else None,
        }


@dataclass
class OperationalHealthReport:
    generated_at: str
    overall_status: str
    health_score: int
    checks: list[HealthCheck] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    issues: list[OperationalHealthIssue] = field(default_factory=list)
    root_cause_ranking: list[dict[str, Any]] = field(default_factory=list)
    primary_cause: OperationalHealthIssue | None = None
    components: list[OperationalComponentHealth] = field(default_factory=list)
    security_degraded_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "health_score": self.health_score,
            "checks": [check.to_dict() for check in self.checks],
            "details": self.details,
            "issues": [issue.to_dict() for issue in self.issues],
            "root_cause_ranking": self.root_cause_ranking,
            "primary_cause": self.primary_cause.to_dict() if self.primary_cause else None,
            "components": [component.to_dict() for component in self.components],
            "security_degraded_mode": self.security_degraded_mode,
            "display_status": self.display_status,
        }

    @property
    def display_status(self) -> str:
        if self.security_degraded_mode:
            return "SECURITY DEGRADED MODE"
        if self.overall_status in {"degraded", "broken", "critical"} and self.primary_cause:
            return f"{self.overall_status.title()} ({self.primary_cause.title})"
        return self.overall_status

    def render_text(self) -> str:
        lines = [
            "Operational Health Dashboard",
            f"Generated: {self.generated_at}",
            f"Overall status: {self.display_status}",
            f"Health score: {self.health_score}/100",
            "",
        ]
        if self.security_degraded_mode:
            lines.extend(
                [
                    "Possible program modification or tampering detected.",
                    "Review the integrity report, preserve evidence, and reinstall from a trusted source if this was not an approved update.",
                    "",
                ]
            )
        if self.primary_cause:
            lines.extend(
                [
                    "Why this is happening:",
                    f"- {self.primary_cause.title}: {self.primary_cause.description}",
                    "What you can do:",
                    f"- {self.primary_cause.suggested_fix[0] if self.primary_cause.suggested_fix else 'Review evidence before taking action.'}",
                    "",
                ]
            )
        for check in self.checks:
            lines.append(f"[{check.status.upper()}] {check.component}: {check.summary}")
            if check.evidence:
                lines.append(f"  Evidence: {check.evidence}")
            if check.next_step:
                lines.append(f"  Next step: {check.next_step}")
        return "\n".join(lines)


class OperationalHealthEngine:
    def __init__(
        self,
        db: AuditDatabase,
        *,
        user_launch_agent: LaunchAgentManager,
        system_launch_agent: LaunchAgentManager,
        notification_manager: NotificationManager | None = None,
        system_readiness: SystemMonitorReadiness | None = None,
        cve_radar_engine: CveRadarEngine | None = None,
        reports_dir: Path | None = None,
        health_log_path: Path | None = None,
    ) -> None:
        self.db = db
        self.user_launch_agent = user_launch_agent
        self.system_launch_agent = system_launch_agent
        self.notification_manager = notification_manager or NotificationManager(db)
        self.system_readiness = system_readiness or SystemMonitorReadiness(db.path)
        self.cve_radar_engine = cve_radar_engine or CveRadarEngine(db)
        self.reports_dir = reports_dir or (Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "reports")
        self.health_log_path = health_log_path or (Path.home() / "Library" / "Logs" / "MacAuditAgent" / "operational_health.log")

    def build_report(self) -> OperationalHealthReport:
        checks: list[HealthCheck] = []
        details: dict[str, Any] = {}
        generated_at = datetime.now(timezone.utc).isoformat()

        checks.append(self._app_health())
        checks.append(self._source_integrity_health())
        checks.append(self._sqlite_health())
        checks.append(self._rule_registry_health())
        checks.append(self._monitor_health())
        checks.append(self._notifier_health())
        checks.append(self._launchagent_health())
        checks.append(self._launchdaemon_health())
        checks.append(self._detector_health())
        checks.append(self._forecast_health())
        checks.append(self._report_export_health())

        score = self._score(checks)
        details["rule_registry"] = rule_registry_summary()
        details["database_path"] = str(self.db.path)
        details["reports_dir"] = str(self.reports_dir)
        details["source_integrity"] = verify_source_integrity(self.db)
        analysis = analyze_operational_health(checks)
        components = self._component_breakdown(checks, generated_at)
        security_degraded_mode = any(issue.risk_of_tampering for issue in analysis.issues)
        overall_status = "critical" if security_degraded_mode else self._overall_status(checks)
        report = OperationalHealthReport(
            generated_at=generated_at,
            overall_status=overall_status,
            health_score=score,
            checks=checks,
            details=details,
            issues=analysis.issues,
            root_cause_ranking=analysis.root_cause_ranking,
            primary_cause=analysis.primary_cause,
            components=components,
            security_degraded_mode=security_degraded_mode,
        )
        self._log_health_state_change(report)
        return report

    def _app_health(self) -> HealthCheck:
        git_commit = current_git_commit()
        status = "healthy" if APP_VERSION and git_commit else "degraded"
        return HealthCheck(
            component="App",
            status=status,
            summary=f"Version {APP_VERSION} commit {git_commit}",
            evidence="Application modules imported successfully.",
            next_step="Review the release checklist before publishing.",
        )

    def _source_integrity_health(self) -> HealthCheck:
        try:
            integrity = verify_source_integrity(self.db)
        except Exception as exc:
            return HealthCheck(
                "Source Integrity",
                "degraded",
                "Integrity verifier failed with an exact error.",
                str(exc),
                "Run Source Integrity Diagnostics before trusting or replacing any manifest.",
            )
        integrity_status = str(integrity.get("overall_status") or integrity.get("status") or "unknown")
        evidence_items = [
            f"status={integrity_status}",
            f"mode={integrity.get('source_type', 'source_tree')}",
            f"trust={integrity.get('trust_state', 'unknown')}",
            f"manifest={integrity.get('manifest_path', '') or 'store'}",
            f"app={integrity.get('manifest_app_version', '') or 'unknown'}->{integrity.get('current_app_version', '') or APP_VERSION}",
            f"build={integrity.get('manifest_build_id', '') or 'unknown'}->{integrity.get('current_build_id', '') or 'unknown'}",
            f"git={str(integrity.get('manifest_git_commit', ''))[:12] or 'unknown'}->{str(integrity.get('current_git_commit', ''))[:12] or 'unknown'}",
            f"reason={integrity.get('exact_mismatch_reason', '') or 'none'}",
            f"files={integrity.get('file_count', 0)}",
            f"matched={integrity.get('matched_count', 0)}",
            f"changed={len(integrity.get('changed_files', []))}",
            f"missing={len(integrity.get('missing_files', []))}",
            f"added={len(integrity.get('added_files', []))}",
            f"skipped={integrity.get('skipped_count', 0)}",
        ]
        if integrity_status == "modified" or integrity.get("tamper_detected"):
            changed = [*integrity.get("changed_files", []), *integrity.get("missing_files", []), *integrity.get("added_files", [])]
            return HealthCheck(
                "Source Integrity",
                "critical",
                "Possible program modification or tampering detected.",
                "; ".join([*evidence_items, ", ".join(str(item) for item in changed[:5])]),
                "Preserve evidence, view mismatches, and reinstall from a trusted source if this change was not approved.",
                "integrity_mismatch",
                False,
                False,
                True,
            )
        if integrity.get("status") == "baseline-created":
            return HealthCheck(
                "Source Integrity",
                "repair recommended",
                "Created initial Python source integrity baseline.",
                "; ".join(evidence_items),
                "Treat this baseline as trusted only if the current source tree is known good.",
            )
        health_status = INTEGRITY_HEALTH_BY_STATUS.get(integrity_status, "degraded")
        if integrity_status not in {"verified", "verified_with_warnings"}:
            recommended = integrity.get("recommended_actions") or ["Run Source Integrity Diagnostics."]
            exact_reason = str(integrity.get("exact_mismatch_reason") or "")
            evidence = "; ".join(
                [
                    *evidence_items,
                    *([f"exact={exact_reason}"] if exact_reason else []),
                    *[str(item) for item in integrity.get("warnings", [])[:2]],
                    *[str(item) for item in integrity.get("errors", [])[:2]],
                ]
            )
            return HealthCheck(
                "Source Integrity",
                health_status,
                INTEGRITY_SUMMARY_BY_STATUS.get(integrity_status, "Source integrity state requires review."),
                evidence,
                str(recommended[0]),
                "integrity_mismatch" if integrity_status in {"stale", "incompatible_manifest", "expired", "revoked", "failed", "modified"} else "configuration",
                integrity_status in {"unknown", "draft", "stale"},
                False,
                integrity_status in {"expired", "revoked", "modified"},
            )
        return HealthCheck(
            "Source Integrity",
            "healthy",
            INTEGRITY_SUMMARY_BY_STATUS.get(integrity_status, INTEGRITY_SUMMARY_BY_STATUS["verified"]),
            "; ".join(evidence_items),
            "Recalculate trusted hashes only after an intentional trusted update.",
        )

    def _sqlite_health(self) -> HealthCheck:
        try:
            quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
            quick_value = str(quick[0] if quick else "")
            tables = {str(row["name"]) for row in self.db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            expected = {"background_monitor_events", "background_monitor_state", "apple_security_forecasts", "investigation_notes"}
            missing = sorted(expected - tables)
            if quick_value.lower() != "ok":
                return HealthCheck("SQLite", "broken", f"quick_check returned {quick_value or 'no result'}", "Database integrity check failed.", "Inspect or restore the database.", "database_issue")
            if missing:
                return HealthCheck("SQLite", "degraded", f"Tables missing: {', '.join(missing)}", "Schema is incomplete or old.", "Run schema migration or repair.", "database_issue", True)
            return HealthCheck("SQLite", "healthy", "Database integrity and tables look healthy.", f"Tables present: {len(tables)}", "Keep backups and avoid destructive cleanup.")
        except Exception as exc:
            return HealthCheck("SQLite", "broken", "Unable to read database health.", str(exc), "Fix file permissions or restore the database.", "database_issue")

    def _rule_registry_health(self) -> HealthCheck:
        summary = rule_registry_summary()
        problem_count = int(summary.get("validation_problem_count", 0))
        status = "healthy" if problem_count == 0 else "degraded"
        return HealthCheck(
            "Rule Registry",
            status,
            f"{summary.get('rule_count', 0)} rules registered; {problem_count} validation problems.",
            ", ".join(summary.get("validation_problems", [])[:3]) or "All required rule metadata is present.",
            "Fix rule metadata before relying on any missing-rule fallback.",
        )

    def _monitor_health(self) -> HealthCheck:
        try:
            readiness = self.system_readiness.audit_deployment()
            status = "healthy" if readiness.deployment_state == "Healthy" else ("repair recommended" if readiness.deployment_state == "Repair Recommended" else "degraded")
            return HealthCheck(
                "System Monitor",
                status,
                f"{readiness.deployment_state} ({readiness.health_score}/100)",
                "Deployment audit completed.",
                "Audit or repair deployment if the monitor is not healthy.",
            )
        except Exception as exc:
            return HealthCheck("System Monitor", "broken", "Deployment audit failed.", str(exc), "Open the deployment audit and repair mismatches.")

    def _notifier_health(self) -> HealthCheck:
        status = self.notification_manager.status()
        visible = self.db.get_background_monitor_state("show_visible_alerts", "1") != "0"
        current = self.db.get_background_monitor_state("notification_status", status)
        if "unavailable" in status.lower():
            return HealthCheck("Notifier", "degraded", status, current, "Install or repair the user notifier / AppleScript path.", "notifier_failure", True)
        if not visible:
            return HealthCheck("Notifier", "disabled_by_settings", "Visible alerts are disabled by preference.", current, "Use Settings to enable bottom-right alerts if you expect notifications.")
        return HealthCheck("Notifier", "healthy", status, current, "Keep the notifier loaded in the logged-in session.")

    def _launchagent_health(self) -> HealthCheck:
        status = self.user_launch_agent.status()
        if not status.installed:
            return HealthCheck("User LaunchAgent", "degraded", "User notifier is not installed.", status.last_error or status.plist_path, "Install the user notifier.", "missing_component", True)
        if not status.loaded and not status.running:
            return HealthCheck("User LaunchAgent", "repair recommended", "Installed but not loaded.", status.last_error or status.plist_path, "Start or repair the user notifier.", "notifier_failure", True)
        return HealthCheck("User LaunchAgent", "healthy", "User notifier is installed and loaded.", status.plist_path, "No action required.")

    def _launchdaemon_health(self) -> HealthCheck:
        status = self.system_launch_agent.status()
        mode = self.db.get_background_monitor_state("monitor_mode", self.db.get_background_monitor_state("monitor_install_mode", "user"))
        if mode not in {"system", "protected"} and not status.installed:
            return HealthCheck("System LaunchDaemon", "disabled_by_settings", "System daemon mode is not enabled.", status.plist_path, "Enable System Monitor Mode only if boot-level monitoring is required.")
        if not status.installed:
            return HealthCheck("System LaunchDaemon", "degraded", "System daemon is not installed.", status.last_error or status.plist_path, "Install the system daemon only when explicitly requested.", "daemon_failure", False, True)
        if not status.loaded and not status.running:
            return HealthCheck("System LaunchDaemon", "repair recommended", "Installed but not loaded.", status.last_error or status.plist_path, "Start or repair the system daemon.", "daemon_failure", False, True)
        return HealthCheck("System LaunchDaemon", "healthy", "System daemon is installed and loaded.", status.plist_path, "No action required.")

    def _detector_health(self) -> HealthCheck:
        status = self.db.get_background_monitor_status()
        if not status.detector_last_run_timestamp:
            return HealthCheck("Detector", "degraded", "Detector has not reported a run timestamp yet.", status.detector_last_zero_reason or status.detector_errors or "none", "Run the monitor and verify event flow.", "runtime_failure")
        if status.detector_errors:
            return HealthCheck("Detector", "repair recommended", "Detector reported errors.", status.detector_errors, "Review detector errors and restart if needed.", "runtime_failure")
        return HealthCheck("Detector", "healthy", "Detector ran and reported events.", status.detector_last_run_timestamp, "No action required.")

    def _forecast_health(self) -> HealthCheck:
        try:
            cached = self.cve_radar_engine.load_cached_state()
            status = str(cached.get("catalog_update_status", "unknown"))
            cards = int(cached.get("cards_count", 0) or 0)
            errors = cached.get("errors", []) or []
            if errors and not cards:
                return HealthCheck("Apple Exposure Assessment", "degraded", "Forecast cache has errors and no cards.", status, "Refresh the assessment or wait for a cache update.", "runtime_failure", True)
            if status in {"offline-cache", "offline-rules"}:
                return HealthCheck("Apple Exposure Assessment", "degraded", f"Using cache ({cards} cards).", status, "Refresh when the network is available.", "runtime_failure", True)
            return HealthCheck("Apple Exposure Assessment", "healthy", f"Forecast cache status: {status} ({cards} cards).", status, "No action required.")
        except Exception as exc:
            return HealthCheck("Apple Exposure Assessment", "broken", "Forecast health unavailable.", str(exc), "Open the assessment tab and try a manual refresh.")

    def _report_export_health(self) -> HealthCheck:
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            writable = os.access(self.reports_dir, os.W_OK)
            if not writable:
                return HealthCheck("Report Export", "degraded", "Reports directory is not writable.", str(self.reports_dir), "Fix permissions on the reports folder.", "permission_issue", True)
            return HealthCheck("Report Export", "healthy", "Reports directory is writable.", str(self.reports_dir), "No action required.")
        except Exception as exc:
            return HealthCheck("Report Export", "broken", "Report export path unavailable.", str(exc), "Restore the reports directory.")

    def _overall_status(self, checks: list[HealthCheck]) -> str:
        statuses = {check.status for check in checks}
        if "critical" in statuses:
            return "critical"
        if "broken" in statuses:
            return "broken"
        if "degraded" in statuses or "unknown" in statuses:
            return "degraded"
        worst = min((STATUS_ORDER.get(check.status, 1) for check in checks), default=1)
        if worst <= STATUS_ORDER["broken"]:
            return "broken"
        if worst <= STATUS_ORDER["degraded"]:
            return "unknown"
        if worst <= STATUS_ORDER["repair recommended"]:
            return "repair recommended"
        return "healthy"

    def _score(self, checks: list[HealthCheck]) -> int:
        weights = {
            "App": 10,
            "Source Integrity": 10,
            "SQLite": 15,
            "Rule Registry": 10,
            "System Monitor": 15,
            "Notifier": 10,
            "User LaunchAgent": 10,
            "System LaunchDaemon": 10,
            "Detector": 10,
            "Apple Exposure Assessment": 10,
            "Report Export": 10,
        }
        total = sum(weights.values()) or 1
        earned = 0
        for check in checks:
            weight = weights.get(check.component, 0)
            status_score = {"healthy": 1.0, "disabled_by_settings": 1.0, "unsupported": 1.0, "repair recommended": 0.6, "unavailable": 0.5, "unknown": 0.4, "degraded": 0.4, "broken": 0.0, "critical": 0.0}.get(check.status, 0.4)
            earned += weight * status_score
        return max(0, min(100, round((earned / total) * 100)))

    def _component_breakdown(self, checks: list[HealthCheck], generated_at: str) -> list[OperationalComponentHealth]:
        labels = {
            "System Monitor": "System Monitor Daemon",
            "Notifier": "User Notifier",
            "Source Integrity": "Integrity Verification",
            "SQLite": "Database",
            "Apple Exposure Assessment": "Apple Exposure",
            "Detector": "USB/Bluetooth Monitor",
            "Rule Registry": "Alert Pipeline",
        }
        components: list[OperationalComponentHealth] = []
        seen: set[str] = set()
        for check in checks:
            name = labels.get(check.component, check.component)
            seen.add(name)
            components.append(
                OperationalComponentHealth(
                    component=name,
                    status=check.status,
                    status_label=check.status.replace("_", " ").title(),
                    reason=check.summary or check.evidence or "No detail available.",
                    last_check_timestamp=generated_at,
                    fix_label=_fix_label_for_check(check),
                    auto_fixable=check.auto_fixable,
                    requires_admin=check.requires_admin,
                    risk_of_tampering=check.risk_of_tampering,
                )
            )
        for required in ["Settings System", "Network Monitor"]:
            if required not in seen:
                components.append(
                    OperationalComponentHealth(required, "healthy", "Healthy", "No unresolved issue reported by Operational Health.", generated_at)
                )
        return components

    def _log_health_state_change(self, report: OperationalHealthReport) -> None:
        before = self.db.get_background_monitor_state("operational_health_last_state", "unknown")
        after = report.overall_status
        primary = report.primary_cause
        if before == after and not primary:
            return
        evidence_ref = f"operational-health-{report.generated_at}"
        entry = {
            "health_state_before": before,
            "health_state_after": after,
            "reason": primary.title if primary else report.display_status,
            "component_affected": primary.component if primary else "",
            "timestamp": report.generated_at,
            "evidence_snapshot_reference": evidence_ref,
            "security_degraded_mode": report.security_degraded_mode,
        }
        self.db.set_background_monitor_state("operational_health_last_state", after)
        self.db.set_background_monitor_state("operational_health_last_evidence_ref", evidence_ref)
        try:
            self.health_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.health_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception:
            pass


def _fix_label_for_check(check: HealthCheck) -> str:
    if check.risk_of_tampering:
        return "View Evidence"
    component = check.component.lower()
    if "notifier" in component or "launchagent" in component:
        return "Repair Notifier"
    if "monitor" in component or "daemon" in component or "detector" in component:
        return "Restart Monitor" if not check.requires_admin else "Requires Admin"
    if check.component == "SQLite":
        return "Rebuild Database Cache"
    if "integrity" in component:
        return "Re-run Integrity Check"
    if "apple exposure" in component:
        return "Refresh Apple Exposure"
    if "settings" in component:
        return "Re-sync Settings"
    if check.auto_fixable:
        return "Repair"
    return "Review"


def analyze_operational_health(checks: list[HealthCheck] | OperationalHealthReport) -> OperationalHealthAnalysis:
    source_checks = checks.checks if isinstance(checks, OperationalHealthReport) else checks
    issues: list[OperationalHealthIssue] = []
    for check in source_checks:
        status = check.status.lower()
        if status in {"healthy", "disabled_by_settings", "unsupported"}:
            continue
        severity: OperationalHealthState = "critical" if check.risk_of_tampering or status == "critical" else "broken" if status == "broken" else "degraded"
        title = _title_for_check(check)
        evidence = [item.strip() for item in str(check.evidence or "").split(";") if item.strip()]
        if not evidence and check.summary:
            evidence = [check.summary]
        suggested_fix = [check.next_step] if check.next_step else ["Review evidence and choose a safe action."]
        issues.append(
            OperationalHealthIssue(
                issue_id=f"{check.component.lower().replace(' ', '_')}_{status}",
                component=check.component,
                severity=severity,
                category=check.category,
                title=title,
                description=check.summary or "Operational component reported an unhealthy state.",
                impact=_impact_for_check(check),
                evidence=evidence,
                suggested_fix=suggested_fix,
                auto_fixable=check.auto_fixable and not check.risk_of_tampering and not check.requires_admin,
                requires_admin=check.requires_admin,
                risk_of_tampering=check.risk_of_tampering,
                confidence=0.95 if check.risk_of_tampering else 0.85 if check.evidence else 0.7,
            )
        )
    issues.sort(key=lambda issue: (_severity_rank(issue.severity), not issue.risk_of_tampering, not issue.requires_admin, issue.component))
    ranking = [
        {
            "rank": index,
            "issue_id": issue.issue_id,
            "title": issue.title,
            "component": issue.component,
            "severity": issue.severity,
            "confidence": issue.confidence,
            "impact": issue.impact,
        }
        for index, issue in enumerate(issues, start=1)
    ]
    return OperationalHealthAnalysis(issues=issues, root_cause_ranking=ranking, primary_cause=issues[0] if issues else None)


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "broken": 1, "degraded": 2, "unknown": 3, "healthy": 4}.get(severity, 3)


def _title_for_check(check: HealthCheck) -> str:
    if check.risk_of_tampering:
        return "Integrity Verification Mismatch"
    summary = check.summary.lower()
    component = check.component.lower()
    if "not installed" in summary or "missing" in summary:
        return f"{check.component} Missing"
    if "not loaded" in summary or "not reported" in summary:
        return f"{check.component} Not Responding"
    if "not writable" in summary or "permission" in summary:
        return f"{check.component} Permission Issue"
    if "settings" in summary or "preference" in summary:
        return "Settings Misconfiguration"
    if "integrity" in component:
        return "Integrity Verification Review Required"
    return f"{check.component} {check.status.replace('_', ' ').title()}"


def _impact_for_check(check: HealthCheck) -> str:
    if check.risk_of_tampering:
        return "CRITICAL: MSAA cannot prove the running program matches trusted files."
    if check.requires_admin:
        return "HIGH: boot-level monitoring may be absent or not responding."
    if check.category in {"notifier_failure", "alert_pipeline_issue"}:
        return "MEDIUM: alerts may be delayed, hidden, or unavailable."
    if check.category == "database_issue":
        return "HIGH: evidence storage or health history may be incomplete."
    return "MEDIUM: monitoring confidence is reduced until this component is fixed."
