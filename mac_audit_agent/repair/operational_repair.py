from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.monitor_settings import load_settings, save_settings
from mac_audit_agent.repair.repair_models import RepairAction, RepairPlan, RepairResult
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import UserNotifierInstaller, update_db_notifier_status


class OperationalRepairEngine:
    def __init__(self, db: AuditDatabase, *, health_engine=None, notifier_installer: UserNotifierInstaller | None = None, log_path: Path | None = None) -> None:
        self.db = db
        self.health_engine = health_engine
        self.notifier_installer = notifier_installer or UserNotifierInstaller(db_path=db.path)
        self.log_path = log_path or (Path.home() / "Library" / "Logs" / "MacAuditAgent" / "repair.log")

    def build_plan(self, health_report: dict[str, Any] | None = None) -> RepairPlan:
        report = health_report or (self.health_engine.build_report().to_dict() if self.health_engine else {"checks": []})
        plan = RepairPlan()
        for issue in report.get("issues", []):
            if not isinstance(issue, dict) or not issue.get("risk_of_tampering"):
                continue
            plan.actions.append(
                RepairAction.create(
                    "Do Not Auto-Fix",
                    str(issue.get("component", "Integrity")),
                    str(issue.get("title", "Possible tampering detected.")),
                    "View evidence, export the integrity report, and reinstall from a trusted source instead of repairing in place.",
                    destructive=True,
                    command_preview="view-integrity-report/export-evidence/reinstall-trusted-version",
                )
            )
            return plan
        settings = load_settings(self.db)
        for check in report.get("checks", []):
            component = str(check.get("component", ""))
            status = str(check.get("status", "")).lower()
            summary = str(check.get("summary", ""))
            evidence = str(check.get("evidence", ""))
            if status in {"healthy", "disabled_by_settings", "unsupported"}:
                continue
            if component in {"Notifier", "User LaunchAgent"} or "notifier" in component.lower():
                if settings.notification.bottom_right_alerts:
                    plan.actions.append(
                        RepairAction.create(
                            "Repair User Alert Agent",
                            "User Notifier",
                            summary or evidence or "User notifier is degraded.",
                            "Recreate the user notifier plist, ensure user log/runtime directories, bootstrap gui/<uid>, and verify status.",
                            command_preview="launchctl bootout/bootstrap gui/<uid> ~/Library/LaunchAgents/com.mac-audit-agent.user-notifier.plist",
                        )
                    )
                else:
                    action = RepairAction.create(
                        "Enable in Settings",
                        "User Notifier",
                        "Bottom-right alerts are disabled by settings.",
                        "Open Settings and enable bottom-right alerts before repairing notifier delivery.",
                    )
                    action.status = "skipped"
                    plan.actions.append(action)
            elif component in {"System Monitor", "System LaunchDaemon"}:
                plan.actions.append(
                    RepairAction.create(
                        "Repair Monitor Daemon",
                        component,
                        summary or evidence or "System monitor is degraded.",
                        "Repair the system LaunchDaemon with administrator approval, then verify heartbeat and DB path.",
                        requires_admin=True,
                        command_preview="sudo launchctl bootout/bootstrap system /Library/LaunchDaemons/com.mac-audit-agent.monitor.plist",
                    )
                )
            elif component == "SQLite":
                plan.actions.append(
                    RepairAction.create(
                        "Repair Database Schema",
                        "Database",
                        summary or evidence or "Database schema is degraded.",
                        "Run safe schema migrations and validate read/write. Do not delete events, findings, reports, or evidence.",
                        command_preview="AuditDatabase(<db_path>) schema migration",
                    )
                )
            elif component == "Report Export":
                plan.actions.append(
                    RepairAction.create(
                        "Repair Report Directories",
                        "Logs/Reports",
                        summary or evidence or "Report directory is unavailable.",
                        "Create missing user report/log directories and verify write access.",
                    )
                )
            elif component == "Apple Exposure Assessment":
                plan.actions.append(
                    RepairAction.create(
                        "Refresh Apple Exposure",
                        "Apple Exposure Assessment",
                        summary or evidence or "Apple Exposure cache is stale or unavailable.",
                        "Refresh Apple Exposure metadata/cache and keep stale cache labeled if refresh fails.",
                    )
                )
            elif "settings" in summary.lower() or "mismatch" in evidence.lower():
                plan.actions.append(
                    RepairAction.create(
                        "Repair Settings Drift",
                        "Settings Drift",
                        summary or evidence,
                        "Re-save MonitorSettings, sync runtime state, and restart notifier/monitor only if needed.",
                    )
                )
        return plan

    def run_safe_repairs(self, plan: RepairPlan) -> RepairResult:
        before = self.health_engine.build_report().overall_status if self.health_engine else ""
        result = RepairResult(before_status=before)
        for action in plan.actions:
            if not action.safe_to_run_automatically:
                action.status = "skipped"
                action.error = "Requires administrator approval or is not safe for automatic repair."
                self._log_action(action)
                result.actions.append(action)
                continue
            action.status = "running"
            try:
                self._run_action(action)
                if action.status == "running":
                    action.status = "succeeded"
                if not action.verification_result:
                    action.verification_result = "Repair action completed and verification did not report failure."
            except Exception as exc:
                action.status = "failed"
                action.error = str(exc)
            self._log_action(action)
            result.actions.append(action)
        result.completed_at = utc_now_iso()
        result.after_status = self.health_engine.build_report().overall_status if self.health_engine else ""
        succeeded = sum(1 for action in result.actions if action.status == "succeeded")
        failed = sum(1 for action in result.actions if action.status == "failed")
        skipped = sum(1 for action in result.actions if action.status == "skipped")
        if failed:
            result.summary = "Repair failed. View diagnostics."
        elif skipped:
            result.summary = "Some issues repaired. Manual action required for remaining items."
        elif succeeded:
            result.summary = "Operational Health repaired successfully."
        else:
            result.summary = "No automatic repairs were run."
        return result

    def _run_action(self, action: RepairAction) -> None:
        if action.component == "User Notifier":
            status = self.notifier_installer.repair_user_notifier()
            update_db_notifier_status(self.db, status)
            action.verification_result = json.dumps(status.to_dict(), sort_keys=True)
            if status.install_status != "loaded":
                raise RuntimeError(status.last_error or "User notifier did not verify as loaded.")
        elif action.component == "Database":
            self.db._init_schema()
            quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
            action.verification_result = str(quick[0] if quick else "")
            if action.verification_result.lower() != "ok":
                raise RuntimeError(f"Database quick_check failed: {action.verification_result}")
        elif action.component == "Logs/Reports":
            for directory in [self.db.logs_dir, self.log_path.parent]:
                directory.mkdir(parents=True, exist_ok=True)
            action.verification_result = f"logs_dir_writable={os.access(self.db.logs_dir, os.W_OK)}"
        elif action.component == "Settings Drift":
            save_settings(self.db, load_settings(self.db))
            action.verification_result = "MonitorSettings re-saved and legacy runtime state synchronized."
        elif action.component == "Apple Exposure Assessment":
            self.db.set_background_monitor_state("apple_exposure_last_repair_attempt_at", utc_now_iso())
            action.verification_result = "Recorded Apple Exposure repair attempt; refresh is handled by the assessment engine."
        else:
            action.status = "skipped"
            action.error = "No safe automatic repair is implemented for this component."

    def _log_action(self, action: RepairAction) -> None:
        self.db.conn.execute(
            """
            INSERT OR REPLACE INTO repair_history (
                repair_id, timestamp, component, issue, action, requires_admin, command_preview,
                status, stdout, stderr, error, verification_result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action.action_id,
                utc_now_iso(),
                action.component,
                action.issue,
                action.title,
                1 if action.requires_admin else 0,
                action.command_preview,
                action.status,
                action.stdout,
                action.stderr,
                action.error,
                action.verification_result,
            ),
        )
        self.db.conn.commit()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(action.to_dict(), sort_keys=True) + "\n")
