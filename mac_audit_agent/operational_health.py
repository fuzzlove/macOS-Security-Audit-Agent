from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.cve_radar import CveRadarEngine
from mac_audit_agent.launch_agent import LaunchAgentManager
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.rules import rule_registry_summary
from mac_audit_agent.source_integrity import verify_source_integrity
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness
from mac_audit_agent.version import APP_VERSION, current_git_commit


STATUS_ORDER = {"healthy": 3, "repair recommended": 2, "degraded": 1, "broken": 0}


@dataclass(frozen=True)
class HealthCheck:
    component: str
    status: str
    summary: str
    evidence: str = ""
    next_step: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OperationalHealthReport:
    generated_at: str
    overall_status: str
    health_score: int
    checks: list[HealthCheck] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "health_score": self.health_score,
            "checks": [check.to_dict() for check in self.checks],
            "details": self.details,
        }

    def render_text(self) -> str:
        lines = [
            "Operational Health Dashboard",
            f"Generated: {self.generated_at}",
            f"Overall status: {self.overall_status}",
            f"Health score: {self.health_score}/100",
            "",
        ]
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
    ) -> None:
        self.db = db
        self.user_launch_agent = user_launch_agent
        self.system_launch_agent = system_launch_agent
        self.notification_manager = notification_manager or NotificationManager(db)
        self.system_readiness = system_readiness or SystemMonitorReadiness(db.path)
        self.cve_radar_engine = cve_radar_engine or CveRadarEngine(db)
        self.reports_dir = reports_dir or (Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "reports")

    def build_report(self) -> OperationalHealthReport:
        checks: list[HealthCheck] = []
        details: dict[str, Any] = {}

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
        return OperationalHealthReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            overall_status=self._overall_status(checks),
            health_score=score,
            checks=checks,
            details=details,
        )

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
            return HealthCheck("Source Integrity", "broken", "Unable to verify Python source hashes.", str(exc), "Rebuild the trusted source baseline from a known-good copy.")
        evidence_items = [
            f"files={integrity.get('file_count', 0)}",
            f"root={str(integrity.get('merkle_root_sha3_512', ''))[:16]}",
            f"changed={len(integrity.get('changed_files', []))}",
            f"missing={len(integrity.get('missing_files', []))}",
            f"added={len(integrity.get('added_files', []))}",
        ]
        if integrity.get("tamper_detected"):
            changed = [*integrity.get("changed_files", []), *integrity.get("missing_files", []), *integrity.get("added_files", [])]
            return HealthCheck(
                "Source Integrity",
                "broken",
                "Python source hash drift detected.",
                "; ".join([*evidence_items, ", ".join(str(item) for item in changed[:5])]),
                "Compare against a trusted release and rebuild the baseline only after validation.",
            )
        if integrity.get("status") == "baseline-created":
            return HealthCheck(
                "Source Integrity",
                "repair recommended",
                "Created initial Python source integrity baseline.",
                "; ".join(evidence_items),
                "Treat this baseline as trusted only if the current source tree is known good.",
            )
        return HealthCheck(
            "Source Integrity",
            "healthy",
            "Python source hashes match the trusted baseline.",
            "; ".join(evidence_items),
            "Rebuild the baseline after intentional source updates.",
        )

    def _sqlite_health(self) -> HealthCheck:
        try:
            quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
            quick_value = str(quick[0] if quick else "")
            tables = {str(row["name"]) for row in self.db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            expected = {"background_monitor_events", "background_monitor_state", "apple_security_forecasts", "investigation_notes"}
            missing = sorted(expected - tables)
            if quick_value.lower() != "ok":
                return HealthCheck("SQLite", "broken", f"quick_check returned {quick_value or 'no result'}", "Database integrity check failed.", "Inspect or restore the database.")
            if missing:
                return HealthCheck("SQLite", "degraded", f"Tables missing: {', '.join(missing)}", "Schema is incomplete or old.", "Run schema migration or repair.")
            return HealthCheck("SQLite", "healthy", "Database integrity and tables look healthy.", f"Tables present: {len(tables)}", "Keep backups and avoid destructive cleanup.")
        except Exception as exc:
            return HealthCheck("SQLite", "broken", "Unable to read database health.", str(exc), "Fix file permissions or restore the database.")

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
            return HealthCheck("Notifier", "degraded", status, current, "Install or repair the user notifier / AppleScript path.")
        if not visible:
            return HealthCheck("Notifier", "degraded", "Visible alerts are disabled by preference.", current, "Re-enable bottom-right alerts if you expect notifications.")
        return HealthCheck("Notifier", "healthy", status, current, "Keep the notifier loaded in the logged-in session.")

    def _launchagent_health(self) -> HealthCheck:
        status = self.user_launch_agent.status()
        if not status.installed:
            return HealthCheck("User LaunchAgent", "degraded", "User notifier is not installed.", status.last_error or status.plist_path, "Install the user notifier.")
        if not status.loaded and not status.running:
            return HealthCheck("User LaunchAgent", "repair recommended", "Installed but not loaded.", status.last_error or status.plist_path, "Start or repair the user notifier.")
        return HealthCheck("User LaunchAgent", "healthy", "User notifier is installed and loaded.", status.plist_path, "No action required.")

    def _launchdaemon_health(self) -> HealthCheck:
        status = self.system_launch_agent.status()
        if not status.installed:
            return HealthCheck("System LaunchDaemon", "degraded", "System daemon is not installed.", status.last_error or status.plist_path, "Install the system daemon only when explicitly requested.")
        if not status.loaded and not status.running:
            return HealthCheck("System LaunchDaemon", "repair recommended", "Installed but not loaded.", status.last_error or status.plist_path, "Start or repair the system daemon.")
        return HealthCheck("System LaunchDaemon", "healthy", "System daemon is installed and loaded.", status.plist_path, "No action required.")

    def _detector_health(self) -> HealthCheck:
        status = self.db.get_background_monitor_status()
        if not status.detector_last_run_timestamp:
            return HealthCheck("Detector", "degraded", "Detector has not reported a run timestamp yet.", status.detector_last_zero_reason or status.detector_errors or "none", "Run the monitor and verify event flow.")
        if status.detector_errors:
            return HealthCheck("Detector", "repair recommended", "Detector reported errors.", status.detector_errors, "Review detector errors and restart if needed.")
        return HealthCheck("Detector", "healthy", "Detector ran and reported events.", status.detector_last_run_timestamp, "No action required.")

    def _forecast_health(self) -> HealthCheck:
        try:
            cached = self.cve_radar_engine.load_cached_state()
            status = str(cached.get("catalog_update_status", "unknown"))
            cards = int(cached.get("cards_count", 0) or 0)
            errors = cached.get("errors", []) or []
            if errors and not cards:
                return HealthCheck("Apple Security Forecast", "degraded", "Forecast cache has errors and no cards.", status, "Refresh the forecast or wait for a cache update.")
            if status in {"offline-cache", "offline-rules"}:
                return HealthCheck("Apple Security Forecast", "degraded", f"Using cache ({cards} cards).", status, "Refresh when the network is available.")
            return HealthCheck("Apple Security Forecast", "healthy", f"Forecast cache status: {status} ({cards} cards).", status, "No action required.")
        except Exception as exc:
            return HealthCheck("Apple Security Forecast", "broken", "Forecast health unavailable.", str(exc), "Open the forecast tab and try a manual refresh.")

    def _report_export_health(self) -> HealthCheck:
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            writable = os.access(self.reports_dir, os.W_OK)
            if not writable:
                return HealthCheck("Report Export", "degraded", "Reports directory is not writable.", str(self.reports_dir), "Fix permissions on the reports folder.")
            return HealthCheck("Report Export", "healthy", "Reports directory is writable.", str(self.reports_dir), "No action required.")
        except Exception as exc:
            return HealthCheck("Report Export", "broken", "Report export path unavailable.", str(exc), "Restore the reports directory.")

    def _overall_status(self, checks: list[HealthCheck]) -> str:
        worst = min((STATUS_ORDER.get(check.status, 1) for check in checks), default=1)
        if worst <= STATUS_ORDER["broken"]:
            return "broken"
        if worst <= STATUS_ORDER["degraded"]:
            return "degraded"
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
            "Apple Security Forecast": 10,
            "Report Export": 10,
        }
        total = sum(weights.values()) or 1
        earned = 0
        for check in checks:
            weight = weights.get(check.component, 0)
            status_score = {"healthy": 1.0, "repair recommended": 0.6, "degraded": 0.4, "broken": 0.0}.get(check.status, 0.4)
            earned += weight * status_score
        return max(0, min(100, round((earned / total) * 100)))
