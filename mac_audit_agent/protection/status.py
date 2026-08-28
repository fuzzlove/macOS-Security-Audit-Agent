from __future__ import annotations

import os
import plistlib
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import LaunchAgentManager, SYSTEM_DB_PATH, protected_monitor_manifest_path
from mac_audit_agent.user_notifier_installer import UserNotifierInstaller


def _age(value: str) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


def _plist_db_path(path: Path) -> tuple[bool, str, str]:
    if not path.is_file():
        return False, "", "plist missing"
    try:
        data = plistlib.loads(path.read_bytes())
        env = data.get("EnvironmentVariables", {})
        return True, str(env.get("MAC_AUDIT_AGENT_DB_PATH", "")), ""
    except Exception as exc:
        return False, "", f"plist parse failed: {type(exc).__name__}: {exc}"


def _db_status(path: Path) -> dict[str, Any]:
    result = {"path": str(path), "readable": False, "writable": False, "schema_ok": False, "heartbeat": "", "heartbeat_age_seconds": None, "error": ""}
    if not path.is_file():
        result["error"] = "active database is missing"
        return result
    result["readable"] = os.access(path, os.R_OK)
    result["writable"] = os.access(path, os.W_OK)
    try:
        uri = f"file:{path}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            result["schema_ok"] = "background_monitor_state" in tables
            if result["schema_ok"]:
                row = conn.execute("SELECT value FROM background_monitor_state WHERE key='last_heartbeat'").fetchone()
                result["heartbeat"] = str(row[0]) if row else ""
                result["heartbeat_age_seconds"] = _age(result["heartbeat"])
    except sqlite3.Error as exc:
        result["error"] = f"SQLite inspection failed: {exc}"
    return result


@dataclass(frozen=True)
class ActiveProtectionStatus:
    status: str
    active_mode: str
    system_daemon: dict[str, Any]
    user_notifier: dict[str, Any]
    active_db: dict[str, Any]
    settings_alignment: dict[str, Any]
    alert_delivery: dict[str, Any]
    runtime_manifest: dict[str, Any]
    missing_components: tuple[str, ...] = ()
    failed_components: tuple[str, ...] = ()
    recommended_primary_action: str = ""
    recommended_command: str = ""
    repair_available: bool = True
    install_available: bool = True
    first_failure_stage: str = ""
    evidence_path: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    service_watchdog: dict[str, Any] = field(default_factory=dict)
    sensor_health_manager: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_active_protection_status(*, db_path: Path = SYSTEM_DB_PATH, home: Path | None = None, runner=None) -> ActiveProtectionStatus:
    home = Path(home or Path.home())
    manager = LaunchAgentManager(db_path, runner=runner, scope="system")
    daemon = manager.status()
    notifier = UserNotifierInstaller(db_path=db_path, home=home, runner=runner).get_user_notifier_status()
    db = _db_status(db_path)
    daemon_plist_ok, daemon_db, daemon_plist_error = _plist_db_path(Path(daemon.plist_path))
    notifier_plist_ok, notifier_db, notifier_plist_error = _plist_db_path(Path(notifier.plist_path))
    heartbeat_age = db.get("heartbeat_age_seconds")
    daemon_live = daemon.running and heartbeat_age is not None and heartbeat_age <= 120
    notifier_live = notifier.running and notifier.active_db_heartbeat_age_seconds is not None and notifier.active_db_heartbeat_age_seconds <= 120
    daemon_payload = {"installed": daemon.installed, "loaded": daemon.loaded, "running": daemon.running, "pid": daemon.process_pid, "label": daemon.label, "plist_path": daemon.plist_path, "plist_valid": daemon_plist_ok, "db_path": daemon_db, "heartbeat": db.get("heartbeat", ""), "heartbeat_age_seconds": heartbeat_age, "error": daemon.last_error or daemon_plist_error}
    notifier_payload = {"installed": notifier.plist_exists, "loaded": notifier.loaded, "running": notifier.running, "pid": notifier.process_pid, "effective_uid": notifier.process_uid, "target_username": notifier.target_username, "target_uid": notifier.target_uid, "target_home": notifier.target_home, "launchd_domain": notifier.launchctl_domain, "graphical_session_available": notifier.graphical_session_available, "heartbeat_fresh": notifier.heartbeat_fresh, "error_code": notifier.error_code, "label": notifier.label, "plist_path": notifier.plist_path, "plist_valid": notifier.plist_valid, "db_path": notifier_db, "heartbeat_db_path": notifier.heartbeat_db_path, "heartbeat": notifier.active_db_heartbeat, "heartbeat_age_seconds": notifier.active_db_heartbeat_age_seconds, "runtime_manifest_exists": notifier.runtime_manifest_exists, "error": notifier.last_error or notifier_plist_error, "status_source": notifier.status_source, "stale_log_evidence_ignored": notifier.stale_log_evidence}
    manifest_path = protected_monitor_manifest_path("system")
    manifest = {"path": str(manifest_path), "exists": manifest_path.is_file(), "valid": False, "version": "", "error": ""}
    if manifest["exists"]:
        try:
            import json
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.update({"valid": bool(payload.get("manifest_digest_sha512")), "version": str(payload.get("runtime_version", ""))})
        except Exception as exc:
            manifest["error"] = f"manifest parse failed: {exc}"
    aligned = daemon_db == str(db_path) and notifier_db == str(db_path) and manifest["valid"]
    settings = {"ui_version": "current", "daemon_version": manifest["version"], "notifier_version": manifest["version"] if notifier.runtime_manifest_exists else "", "installed_manifest_version": manifest["version"], "daemon_db_path": daemon_db, "notifier_db_path": notifier_db, "aligned": aligned}
    alerts = {"configured": notifier.plist_exists, "deliverable": notifier_live and notifier_db == str(db_path), "last_verified": notifier.active_db_heartbeat}
    from mac_audit_agent.service_watchdog import status_payload as service_watchdog_status

    watchdog = service_watchdog_status()
    watchdog_live = bool(watchdog.get("installed") and watchdog.get("healthy") and watchdog.get("health_fresh"))
    from mac_audit_agent.sensor_health_service import SENSOR_HEALTH_PLIST_PATH, SENSOR_HEALTH_REPORT_PATH

    sensor_health = {"installed": SENSOR_HEALTH_PLIST_PATH.is_file(), "health_path": str(SENSOR_HEALTH_REPORT_PATH), "health_fresh": False, "overall_health": "UNKNOWN", "error": ""}
    if SENSOR_HEALTH_REPORT_PATH.is_file():
        try:
            import json
            health_payload = json.loads(SENSOR_HEALTH_REPORT_PATH.read_text(encoding="utf-8"))
            age = _age(str(health_payload.get("generated_at", "")))
            sensor_health.update({"health_fresh": age is not None and age <= 180, "health_age_seconds": age, "overall_health": str(health_payload.get("overall_health", "UNKNOWN"))})
        except (OSError, ValueError, TypeError) as exc:
            sensor_health["error"] = f"health report unavailable: {type(exc).__name__}"
    sensor_health_live = bool(sensor_health["installed"] and sensor_health["health_fresh"])
    missing: list[str] = []
    failed: list[str] = []
    if not daemon.installed: missing.append("system_daemon")
    elif not daemon_live: failed.append("system_daemon")
    if not notifier.plist_exists: missing.append("user_notifier")
    elif not notifier_live: failed.append("user_notifier")
    if daemon.installed and not watchdog.get("installed"): missing.append("service_watchdog")
    elif watchdog.get("installed") and not watchdog_live: failed.append("service_watchdog")
    if daemon.installed and not sensor_health["installed"]: missing.append("sensor_health_manager")
    elif sensor_health["installed"] and not sensor_health_live: failed.append("sensor_health_manager")
    if not db["schema_ok"]: missing.append("active_db")
    if not manifest["exists"]: missing.append("runtime_manifest")
    if daemon_live and notifier_live and watchdog_live and sensor_health_live and db["schema_ok"] and aligned and alerts["deliverable"]:
        state, mode, action, command, first = "installed_running", "protected", "Protection is running", "python3.12 -m mac_audit_agent.protection doctor --json", ""
    elif not daemon.installed:
        state, mode, action, command, first = "not_installed", "observe", "Install Active Protection", "python3.12 -m mac_audit_agent.protection install --mode protected --with-system-daemon --with-user-notifier --apply-current-settings --verify --verbose", "system_daemon_missing"
    elif not notifier.plist_exists:
        state, mode, action, command, first = "partially_installed", "observe", "Repair User Alert Agent", "python3.12 -m mac_audit_agent.protection repair --mode protected --repair-user-notifier --verify --verbose", "user_notifier_missing"
    elif not aligned:
        state, mode, action, command, first = "degraded", "observe", "Repair Runtime Alignment", "python3.12 -m mac_audit_agent.protection repair --mode protected --repair-settings-sync --verify --verbose", "runtime_alignment"
    else:
        state, mode, action, command, first = "failed", "observe", "Repair Active Protection", "python3.12 -m mac_audit_agent.protection repair --mode protected --repair-system-daemon --repair-user-notifier --repair-settings-sync --verify --verbose", failed[0] if failed else "verification"
    return ActiveProtectionStatus(
        state,
        mode,
        daemon_payload,
        notifier_payload,
        db,
        settings,
        alerts,
        manifest,
        tuple(missing),
        tuple(failed),
        action,
        command,
        True,
        True,
        first,
        "",
        {"status_source": "live_launchctl_plist_sqlite", "historical_logs_are_authoritative": False},
        watchdog,
        sensor_health,
    )


__all__ = ["ActiveProtectionStatus", "resolve_active_protection_status"]
