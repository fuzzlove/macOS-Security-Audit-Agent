from __future__ import annotations

import json
import os
import plistlib
import pwd
import grp
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import (
    LAUNCH_AGENT_LABEL,
    MAC_AUDIT_AGENT_ENV_DB_PATH,
    MONITOR_ROLE_SYSTEM,
    LaunchAgentManager,
    build_launch_agent_plist,
    default_monitor_db_path,
    load_protected_monitor_manifest,
    protected_monitor_manifest_path,
    runtime_monitor_script_path,
    runtime_package_root,
    runtime_root,
    system_monitor_location_status,
)
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.version import APP_VERSION, DATABASE_SCHEMA_VERSION, RUNTIME_MANIFEST_SCHEMA_VERSION, current_git_commit


HEARTBEAT_SECONDS = 30
DEPLOYMENT_EVENT_FLOW_REQUEST_KEY = "deployment_event_flow_request_json"
DEPLOYMENT_EVENT_FLOW_PROCESSED_KEY = "deployment_event_flow_processed_json"
DEPLOYMENT_EVENT_FLOW_EVENT_TYPE = "monitor_deployment_event_flow_test"
DEPLOYMENT_REPAIR_LOG_KEY = "deployment_repair_last_actions_json"


@dataclass
class AuditCheckResult:
    check_id: str
    label: str
    status: str
    expected: str = ""
    observed: str = ""
    details: str = ""
    repair_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "status": self.status,
            "expected": self.expected,
            "observed": self.observed,
            "details": self.details,
            "repair_action": self.repair_action,
        }


@dataclass
class DeploymentAuditReport:
    generated_at: str
    deployment_state: str
    health_score: int
    checks: list[AuditCheckResult] = field(default_factory=list)
    installed_manifest: dict[str, Any] = field(default_factory=dict)
    application_manifest: dict[str, Any] = field(default_factory=dict)
    database_health: list[AuditCheckResult] = field(default_factory=list)
    repair_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "deployment_state": self.deployment_state,
            "health_score": self.health_score,
            "checks": [check.to_dict() for check in self.checks],
            "installed_manifest": self.installed_manifest,
            "application_manifest": self.application_manifest,
            "database_health": [check.to_dict() for check in self.database_health],
            "repair_actions": self.repair_actions,
        }

    def render_text(self) -> str:
        lines = [
            "Deployment Audit Report",
            f"Generated: {self.generated_at}",
            f"Deployment State: {self.deployment_state}",
            f"System Monitor Health Score: {self.health_score}/100",
            "",
        ]
        for check in [*self.checks, *self.database_health]:
            detail = f" | {check.details}" if check.details else ""
            lines.append(f"[{check.status}] {check.label}: expected={check.expected or 'n/a'} observed={check.observed or 'n/a'}{detail}")
        if self.repair_actions:
            lines.extend(["", "Repair Actions:"])
            lines.extend(f"- {action}" for action in self.repair_actions)
        return "\n".join(lines)


@dataclass
class EventFlowVerification:
    generated_at: str
    request_id: str
    stages: list[AuditCheckResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "request_id": self.request_id,
            "stages": [stage.to_dict() for stage in self.stages],
        }

    def render_text(self) -> str:
        lines = ["Event Pipeline Verification", f"Generated: {self.generated_at}", f"Request ID: {self.request_id}", ""]
        for stage in self.stages:
            detail = f" | {stage.details}" if stage.details else ""
            lines.append(f"[{stage.status}] {stage.label}: {stage.observed or 'n/a'}{detail}")
        return "\n".join(lines)


def _safe_json_loads(raw: str, default: Any) -> Any:
    try:
        parsed = json.loads(raw or "")
    except Exception:
        return default
    return parsed if parsed is not None else default


def _path_owner_mode(path: Path) -> tuple[str, str]:
    st = path.stat()
    owner = f"{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}"
    return owner, oct(stat.S_IMODE(st.st_mode))


def _status(ok: bool, fail_status: str = "FAIL") -> str:
    return "PASS" if ok else fail_status


def _is_pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _is_heartbeat_fresh(last_heartbeat: str, max_age_seconds: int = 120) -> bool:
    if not last_heartbeat:
        return False
    try:
        heartbeat = datetime.fromisoformat(last_heartbeat)
    except ValueError:
        return False
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - heartbeat).total_seconds() <= max_age_seconds


class SystemMonitorReadiness:
    def __init__(self, db_path: Path | None = None, runner=None) -> None:
        self.db_path = db_path or default_monitor_db_path("system")
        self.system_manager = LaunchAgentManager(self.db_path, runner=runner, scope="system")
        self.user_notifier_manager = LaunchAgentManager(self.db_path, runner=runner, scope="user")

    def application_manifest(self) -> dict[str, Any]:
        return {
            "runtime_version": APP_VERSION,
            "build_timestamp": "current source",
            "git_commit": current_git_commit(),
            "schema_version": RUNTIME_MANIFEST_SCHEMA_VERSION,
            "database_schema_version": DATABASE_SCHEMA_VERSION,
            "db_path": str(default_monitor_db_path("system")),
            "monitor_script_path": str(runtime_monitor_script_path("system")),
            "runtime_root": str(runtime_root("system")),
        }

    def audit_deployment(self) -> DeploymentAuditReport:
        checks: list[AuditCheckResult] = []
        expected_plist = self.system_manager.paths.plist_path
        expected_runtime = runtime_root("system")
        expected_db = default_monitor_db_path("system")
        expected_payload = build_launch_agent_plist(db_path=expected_db, scope="system", mode=MONITOR_ROLE_SYSTEM)
        plist_payload: dict[str, Any] = {}
        plist_exists = expected_plist.exists()
        checks.append(AuditCheckResult("launchdaemon_exists", "LaunchDaemon exists", _status(plist_exists), str(expected_plist), str(expected_plist if plist_exists else "missing"), repair_action="Install or repair System Monitor"))
        location = system_monitor_location_status(self.system_manager.paths)
        checks.append(AuditCheckResult("launchdaemon_location", "LaunchDaemon installed in system folder", _status(bool(location.get("valid"))), str(location.get("expected_plist_path", "")), str(location.get("observed_plist_path", "")), str(location.get("message", "")), repair_action="Repair System Monitor"))
        if plist_exists:
            try:
                plist_payload = plistlib.loads(expected_plist.read_bytes())
            except Exception as exc:
                checks.append(AuditCheckResult("launchdaemon_plist_parse", "LaunchDaemon plist parses", "FAIL", "valid plist", str(exc), repair_action="Repair System Monitor"))
        runtime_exists = expected_runtime.exists()
        checks.append(AuditCheckResult("runtime_exists", "Runtime exists", _status(runtime_exists), str(expected_runtime), str(expected_runtime if runtime_exists else "missing"), repair_action="Repair System Monitor runtime"))
        db_exists = expected_db.exists()
        checks.append(AuditCheckResult("shared_db_exists", "Shared system DB exists", _status(db_exists, "WARNING"), str(expected_db), str(expected_db if db_exists else "missing"), repair_action="Start monitor or repair DB path"))
        if plist_payload:
            observed_args = plist_payload.get("ProgramArguments", [])
            expected_args = expected_payload.get("ProgramArguments", [])
            checks.append(AuditCheckResult("program_arguments", "ProgramArguments match expected runtime", _status(observed_args == expected_args), json.dumps(expected_args), json.dumps(observed_args), repair_action="Repair System Monitor plist"))
            observed_workdir = str(plist_payload.get("WorkingDirectory", ""))
            expected_workdir = str(expected_payload.get("WorkingDirectory", ""))
            checks.append(AuditCheckResult("working_directory", "WorkingDirectory matches expected runtime", _status(observed_workdir == expected_workdir), expected_workdir, observed_workdir, repair_action="Repair System Monitor plist"))
            observed_db = str(plist_payload.get("EnvironmentVariables", {}).get(MAC_AUDIT_AGENT_ENV_DB_PATH, ""))
            checks.append(AuditCheckResult("database_path", "Database path matches shared system DB", _status(observed_db == str(expected_db)), str(expected_db), observed_db or "missing", repair_action="Repair System Monitor plist"))
        if plist_exists:
            try:
                owner, mode = _path_owner_mode(expected_plist)
                checks.append(AuditCheckResult("launchdaemon_permissions", "LaunchDaemon owner and permissions", _status(owner == "root:wheel" and mode == "0o644"), "root:wheel / 0o644", f"{owner} / {mode}", repair_action="Repair LaunchDaemon ownership and mode"))
            except Exception as exc:
                checks.append(AuditCheckResult("launchdaemon_permissions", "LaunchDaemon owner and permissions", "FAIL", "root:wheel / 0o644", str(exc), repair_action="Repair LaunchDaemon ownership and mode"))
        if runtime_exists:
            try:
                owner, mode = _path_owner_mode(expected_runtime)
                checks.append(AuditCheckResult("runtime_permissions", "Runtime owner and permissions", _status(owner == "root:wheel" and mode in {"0o755", "0o775"}), "root:wheel / not world-writable", f"{owner} / {mode}", repair_action="Repair runtime ownership and mode"))
            except Exception as exc:
                checks.append(AuditCheckResult("runtime_permissions", "Runtime owner and permissions", "FAIL", "root:wheel / not world-writable", str(exc), repair_action="Repair runtime ownership and mode"))
        launch_status = self.system_manager.status()
        checks.append(AuditCheckResult("launchdaemon_loaded", "LaunchDaemon loaded", _status(launch_status.loaded, "WARNING"), "loaded", "loaded" if launch_status.loaded else "not loaded", launch_status.last_error, repair_action="Start System Monitor"))
        pid_alive = _is_pid_alive(launch_status.process_pid)
        checks.append(AuditCheckResult("launchdaemon_pid_alive", "LaunchDaemon PID alive", _status(pid_alive, "WARNING"), "alive PID", str(launch_status.process_pid or "none"), repair_action="Restart System Monitor"))
        db_status = self._db_status()
        heartbeat_fresh = _is_heartbeat_fresh(db_status.get("last_heartbeat", ""), max_age_seconds=max(120, HEARTBEAT_SECONDS * 2))
        checks.append(AuditCheckResult("heartbeat_fresh", "Heartbeat fresh", _status(heartbeat_fresh, "WARNING"), "fresh heartbeat", db_status.get("last_heartbeat", "none"), repair_action="Restart System Monitor"))
        installed_manifest = load_protected_monitor_manifest(scope="system")
        application_manifest = self.application_manifest()
        installed_version = str(installed_manifest.get("runtime_version", "missing"))
        app_version = str(application_manifest.get("runtime_version", ""))
        manifest_ok = installed_version == app_version
        checks.append(AuditCheckResult("runtime_version", "Runtime version matches application", _status(manifest_ok, "WARNING"), app_version, installed_version, repair_action="Repair System Monitor runtime"))
        installed_db = str(installed_manifest.get("db_path", "missing"))
        checks.append(AuditCheckResult("manifest_db_path", "Runtime manifest DB path matches shared system DB", _status(installed_db == str(expected_db), "WARNING"), str(expected_db), installed_db, repair_action="Repair System Monitor runtime"))
        database_health = self.database_health()
        health_score = self.health_score(checks, database_health)
        state = self.deployment_state(checks, database_health)
        repair_actions = sorted({check.repair_action for check in [*checks, *database_health] if check.status in {"FAIL", "WARNING"} and check.repair_action})
        return DeploymentAuditReport(
            generated_at=utc_now_iso(),
            deployment_state=state,
            health_score=health_score,
            checks=checks,
            installed_manifest=installed_manifest,
            application_manifest=application_manifest,
            database_health=database_health,
            repair_actions=repair_actions,
        )

    def _db_status(self) -> dict[str, str]:
        if not self.db_path.exists():
            return {"last_heartbeat": "", "last_event_timestamp": "", "last_error": "shared system DB does not exist"}
        try:
            db = AuditDatabase(self.db_path)
            status = db.get_background_monitor_status()
            return status.to_dict()
        except Exception as exc:
            return {"last_heartbeat": "", "last_event_timestamp": "", "last_error": str(exc)}

    def database_health(self) -> list[AuditCheckResult]:
        checks: list[AuditCheckResult] = []
        db_path = default_monitor_db_path("system")
        checks.append(AuditCheckResult("db_path_exists", "Database path exists", _status(db_path.exists(), "WARNING"), str(db_path), str(db_path if db_path.exists() else "missing"), repair_action="Start monitor or repair DB path"))
        if not db_path.exists():
            return checks
        try:
            db = AuditDatabase(db_path)
            quick = db.conn.execute("PRAGMA quick_check").fetchone()
            quick_value = str(quick[0] if quick else "")
            checks.append(AuditCheckResult("db_quick_check", "Database corruption check", _status(quick_value.lower() == "ok"), "ok", quick_value, repair_action="Review or restore database"))
            tables = {str(row["name"]) for row in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            expected_tables = {"background_monitor_events", "background_monitor_state", "background_monitor_heartbeats"}
            missing = sorted(expected_tables - tables)
            checks.append(AuditCheckResult("db_tables", "Monitor tables exist", _status(not missing), ", ".join(sorted(expected_tables)), ", ".join(sorted(tables & expected_tables)) or "none", f"missing={missing}" if missing else "", repair_action="Repair database schema"))
            db.set_background_monitor_state("deployment_audit_last_db_write_check", utc_now_iso())
            checks.append(AuditCheckResult("db_write_access", "Database write access", "PASS", "write succeeds", "write succeeded"))
            schema = db.get_background_monitor_state("schema_version", "")
            checks.append(AuditCheckResult("db_schema_version", "Expected schema version", _status(schema == str(DATABASE_SCHEMA_VERSION), "WARNING"), str(DATABASE_SCHEMA_VERSION), schema or "missing", repair_action="Open application to migrate schema"))
            latest = db.latest_monitor_event_timestamp()
            checks.append(AuditCheckResult("db_recent_events", "Recent events visible", _status(bool(latest), "WARNING"), "latest event timestamp", latest or "none", repair_action="Verify Event Flow"))
        except Exception as exc:
            checks.append(AuditCheckResult("db_read_write", "Database read/write access", "FAIL", "read/write succeeds", str(exc), repair_action="Repair DB permissions"))
        return checks

    def health_score(self, checks: list[AuditCheckResult], database_health: list[AuditCheckResult]) -> int:
        weights = {
            "launchdaemon_exists": 10,
            "runtime_exists": 10,
            "shared_db_exists": 10,
            "program_arguments": 10,
            "database_path": 10,
            "launchdaemon_permissions": 10,
            "runtime_permissions": 8,
            "launchdaemon_loaded": 8,
            "launchdaemon_pid_alive": 8,
            "heartbeat_fresh": 8,
            "runtime_version": 8,
            "db_quick_check": 6,
            "db_write_access": 4,
            "db_tables": 4,
        }
        total = sum(weights.values())
        earned = 0
        for check in [*checks, *database_health]:
            weight = weights.get(check.check_id, 0)
            if check.status == "PASS":
                earned += weight
            elif check.status == "WARNING":
                earned += int(weight * 0.4)
        return max(0, min(100, round((earned / total) * 100))) if total else 0

    def deployment_state(self, checks: list[AuditCheckResult], database_health: list[AuditCheckResult]) -> str:
        all_checks = [*checks, *database_health]
        fail_ids = {check.check_id for check in all_checks if check.status == "FAIL"}
        warning_ids = {check.check_id for check in all_checks if check.status == "WARNING"}
        if fail_ids & {"launchdaemon_exists", "runtime_exists", "program_arguments", "database_path", "launchdaemon_permissions", "db_quick_check", "db_tables"}:
            return "Broken"
        if fail_ids or warning_ids & {"runtime_version", "manifest_db_path", "heartbeat_fresh", "launchdaemon_loaded", "launchdaemon_pid_alive"}:
            return "Repair Recommended"
        if warning_ids:
            return "Warning"
        return "Healthy"

    def request_event_flow_test(self) -> str:
        request_id = f"event-flow-{int(time.time())}-{os.getpid()}"
        db = AuditDatabase(self.db_path)
        db.set_background_monitor_state(
            DEPLOYMENT_EVENT_FLOW_REQUEST_KEY,
            json.dumps({"request_id": request_id, "created_at": utc_now_iso(), "source": "ui_deployment_verification"}, sort_keys=True),
        )
        return request_id

    def verify_event_flow(self, timeout_seconds: int = 10) -> EventFlowVerification:
        request_id = self.request_event_flow_test()
        stages: list[AuditCheckResult] = []
        launch_status = self.system_manager.status()
        stages.append(AuditCheckResult("daemon_running", "Daemon running", _status(launch_status.running or launch_status.loaded, "FAIL"), "running system daemon", f"loaded={launch_status.loaded} running={launch_status.running} pid={launch_status.process_pid or 'none'}", launch_status.last_error))
        found_event: BackgroundMonitorEvent | None = None
        deadline = time.monotonic() + max(1, timeout_seconds)
        while time.monotonic() < deadline:
            try:
                db = AuditDatabase(self.db_path)
                events = db.recent_background_monitor_events(limit=50, event_type=DEPLOYMENT_EVENT_FLOW_EVENT_TYPE)
                found_event = next((event for event in events if request_id in event.evidence or request_id in event.metadata_json), None)
                if found_event:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        stages.append(AuditCheckResult("daemon_wrote_event", "Daemon writes synthetic event", _status(found_event is not None, "FAIL"), request_id, found_event.event_id if found_event else "not observed"))
        db_visible = False
        ui_visible = False
        notifier_visible = False
        visible_alert_delivered = False
        visible_alert_evidence = "not observed"
        try:
            db = AuditDatabase(self.db_path)
            db_visible = found_event is not None and any(event.event_id == found_event.event_id for event in db.recent_background_monitor_events(limit=100))
            ui_visible = db_visible
            pending = db.pending_background_monitor_events(limit=200)
            notifier_visible = found_event is not None and any(event.event_id == found_event.event_id for event in pending)
            if found_event:
                trace = db.get_event_alert_trace(found_event.event_id)
                deliveries = db.latest_alert_delivery_records(limit=100)
                delivery = next((item for item in deliveries if item.event_id == found_event.event_id), None)
                visible_alert_delivered = bool(
                    getattr(found_event, "visible_alert_shown", False)
                    or (trace and str(trace.overlay_dispatch_result).upper() == "SUCCESS")
                    or (delivery and (delivery.overlay_success or delivery.dialog_success))
                )
                if delivery:
                    visible_alert_evidence = (
                        f"delivery overlay_success={delivery.overlay_success} "
                        f"dialog_success={delivery.dialog_success} method={delivery.delivery_method_used or 'none'}"
                    )
                elif trace:
                    visible_alert_evidence = f"trace overlay_result={trace.overlay_dispatch_result or 'none'} visible_alert_id={trace.visible_alert_id or 'none'}"
                db.update_monitor_event_notification(
                    found_event.event_id,
                    notification_sent=True,
                    notification_error="",
                    notification_returncode=None,
                    notification_decision="deployment_event_flow_verified",
                    notification_reason="Synthetic event flow verification completed without popup.",
                    popup_allowed=False,
                )
        except Exception as exc:
            stages.append(AuditCheckResult("shared_db_receives_event", "Shared DB receives event", "FAIL", "event readable", str(exc)))
        else:
            stages.append(AuditCheckResult("shared_db_receives_event", "Shared DB receives event", _status(db_visible, "FAIL"), "event readable", "readable" if db_visible else "missing"))
            stages.append(AuditCheckResult("ui_reads_event", "UI reads event", _status(ui_visible, "FAIL"), "UI can read shared DB event", "readable" if ui_visible else "missing"))
            notifier_status = self.user_notifier_manager.status()
            stages.append(AuditCheckResult("notifier_receives_event", "Notifier queue receives event", _status(notifier_visible and notifier_status.installed, "WARNING"), "pending event visible and notifier installed", f"pending={notifier_visible} notifier_installed={notifier_status.installed} loaded={notifier_status.loaded}"))
            stages.append(
                AuditCheckResult(
                    "visible_alert_delivery",
                    "Visible alert delivery observed",
                    _status(visible_alert_delivered, "WARNING"),
                    "overlay or dialog delivery success",
                    visible_alert_evidence,
                    "Synthetic deployment verification events are log-only unless a visible-alert test was explicitly routed through notifier/overlay.",
                )
            )
        return EventFlowVerification(generated_at=utc_now_iso(), request_id=request_id, stages=stages)

    def repair_mismatches(self, report: DeploymentAuditReport) -> list[str]:
        if os.geteuid() != 0:
            raise RuntimeError("Repairing System Monitor deployment requires administrator/root approval.")
        actions = list(report.repair_actions)
        if not actions:
            return ["No deployment mismatches require repair."]
        notes: list[str] = []
        if any("System Monitor" in action or "runtime" in action or "LaunchDaemon" in action or "DB path" in action or "ownership" in action for action in actions):
            plist_path = self.system_manager.install_system_monitor()
            notes.append(f"repaired system monitor plist/runtime: {plist_path}")
        if self.system_manager.status().installed:
            self.system_manager.start()
            notes.append("restarted system monitor")
        if not self.user_notifier_manager.status().installed:
            self.user_notifier_manager.install_user_notifier()
            notes.append("installed user notifier")
        try:
            db = AuditDatabase(self.db_path)
            db.set_background_monitor_state(DEPLOYMENT_REPAIR_LOG_KEY, json.dumps({"timestamp": utc_now_iso(), "actions": notes, "requested_repairs": actions}, sort_keys=True))
        except Exception:
            pass
        return notes


def process_deployment_event_flow_request(db: AuditDatabase) -> list[BackgroundMonitorEvent]:
    raw_request = db.get_background_monitor_state(DEPLOYMENT_EVENT_FLOW_REQUEST_KEY, "")
    request = _safe_json_loads(raw_request, {})
    if not isinstance(request, dict):
        return []
    request_id = str(request.get("request_id", "")).strip()
    if not request_id:
        return []
    processed = _safe_json_loads(db.get_background_monitor_state(DEPLOYMENT_EVENT_FLOW_PROCESSED_KEY, ""), {})
    if isinstance(processed, dict) and processed.get("request_id") == request_id:
        return []
    event = BackgroundMonitorEvent(
        event_id=f"deployment-event-flow-{request_id}",
        timestamp=utc_now_iso(),
        event_type=DEPLOYMENT_EVENT_FLOW_EVENT_TYPE,
        severity="info",
        source="system_monitor_deployment",
        evidence=f"Synthetic deployment event flow verification request processed by system daemon: {request_id}",
        confidence="high",
        recommendation="No action required. This is an operational readiness test event.",
        simulated=True,
        metadata_json=json.dumps({"request_id": request_id, "source": "system_daemon"}, sort_keys=True),
        notification_decision="log_only",
        notification_reason="Synthetic deployment verification event; no popup.",
        popup_allowed=False,
    )
    db.record_monitor_event(event, dedupe_window_seconds=0)
    db.set_background_monitor_state(DEPLOYMENT_EVENT_FLOW_PROCESSED_KEY, json.dumps({"request_id": request_id, "processed_at": event.timestamp, "event_id": event.event_id}, sort_keys=True))
    return [event]
