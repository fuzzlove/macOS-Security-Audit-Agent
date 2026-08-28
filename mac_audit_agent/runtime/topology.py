from __future__ import annotations

import os
import plistlib
import platform
import sqlite3
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from mac_audit_agent.version import APP_VERSION, current_git_commit

MonitorMode = Literal["user", "system"]

SYSTEM_DB = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
SYSTEM_RUNTIME = Path("/Library/Application Support/MacAuditAgent/runtime")
SYSTEM_LOGS = Path("/Library/Logs/MacAuditAgent")
SYSTEM_PLIST = Path("/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist")
MONITOR_LABEL = "com.mac-audit-agent.monitor"
NOTIFIER_LABEL = "com.mac-audit-agent.user-notifier"


@dataclass(frozen=True)
class RuntimeTopology:
    selected_monitor_mode: MonitorMode
    requested_monitor_mode: MonitorMode
    effective_monitor_mode: str
    actual_installed_monitor_mode: str
    installed_monitor_services: tuple[str, ...]
    conflicting_monitor_modes: tuple[str, ...]
    canonical_event_database: str
    settings_storage_database: str
    alert_trace_database: str
    notifier_transport: str
    notifier_event_database: str
    notifier_receipt_database: str
    acknowledgement_store: str
    receipt_producer: str
    receipt_consumer: str
    process_executable: str
    service_executable: str
    notifier_executable: str
    monitor_program_arguments: tuple[str, ...]
    notifier_program_arguments: tuple[str, ...]
    application_mode: str
    service_execution_mode: str
    monitor_launchctl_domain: str
    notifier_launchctl_domain: str
    monitor_service_label: str
    notifier_service_label: str
    working_directory: str
    effective_settings_version: str
    expected_event_db_owner: str
    expected_event_db_group: str
    expected_event_db_mode: str
    expected_settings_owner: str
    expected_settings_mode: str
    monitor_requires_elevated_privileges: bool
    notifier_requires_elevated_privileges: bool
    executable_architecture: str
    build_id: str
    application_version: str
    monitor_plist_path: str
    notifier_plist_path: str
    monitor_stdout_path: str
    monitor_stderr_path: str
    notifier_stdout_path: str
    notifier_stderr_path: str
    aligned: bool
    error_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeHealth:
    healthy: bool
    error_codes: tuple[str, ...]
    details: tuple[str, ...]


def evaluate_runtime_health(
    topology: RuntimeTopology,
    *,
    monitor_installed: bool,
    monitor_loaded: bool,
    monitor_running: bool,
    monitor_heartbeat: str = "",
    heartbeat_max_age_seconds: int = 90,
    notifier_heartbeat_fresh: bool = True,
    notifier_received_test_event: bool | None = None,
) -> RuntimeHealth:
    codes = list(topology.error_codes)
    details: list[str] = []
    if topology.selected_monitor_mode == "system":
        if not monitor_installed:
            codes.append("MON001")
            details.append("system daemon is not installed")
        elif not monitor_loaded:
            codes.append("MON002")
            details.append("system daemon is not loaded")
        elif not monitor_running:
            codes.append("MON003")
            details.append("system daemon is not running")
        if not _fresh_timestamp(monitor_heartbeat, heartbeat_max_age_seconds):
            codes.append("MON004")
            details.append("system daemon heartbeat is stale or missing")
    if not notifier_heartbeat_fresh:
        codes.append("ALT002")
        details.append("user notifier heartbeat is stale")
    if notifier_received_test_event is False:
        codes.append("ALT003")
        details.append("user notifier did not receive the diagnostic event")
    unique = tuple(dict.fromkeys(codes))
    return RuntimeHealth(healthy=not unique, error_codes=unique, details=tuple(details))


def _fresh_timestamp(value: str, max_age_seconds: int) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return False
        return 0 <= (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() <= max_age_seconds
    except (TypeError, ValueError):
        return False


def user_home(uid: int | None = None) -> Path:
    if uid is None or uid == os.getuid():
        return Path.home()
    import pwd

    return Path(pwd.getpwuid(uid).pw_dir)


def user_settings_db(home: Path | None = None) -> Path:
    return Path(home or Path.home()) / ".mac_audit_agent.sqlite3"


def resolve_runtime_topology(
    settings_db_path: Path | None = None,
    *,
    selected_mode: str | None = None,
    actual_installed_mode: str | None = None,
    notifier_event_database: Path | None = None,
    frozen: bool | None = None,
    executable: str | None = None,
    monitor_executable: str | None = None,
    notifier_executable: str | None = None,
    execution_mode: str | None = None,
    uid: int | None = None,
    home: Path | None = None,
) -> RuntimeTopology:
    home = Path(home).expanduser() if home is not None else user_home(uid)
    settings_db = Path(settings_db_path or user_settings_db(home)).expanduser()
    selected = _normalize_mode(selected_mode or _state_value(settings_db, "monitor_mode") or _state_value(settings_db, "monitor_install_mode") or "user")
    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)
    process_executable = os.path.abspath(executable or sys.executable)
    monitor_program = os.path.abspath(monitor_executable or process_executable)
    notifier_program = os.path.abspath(notifier_executable or process_executable)
    actual = actual_installed_mode or _installed_mode(home)
    event_db = SYSTEM_DB if selected == "system" else settings_db
    receipt_db = home / "Library" / "Application Support" / "MacAuditAgent" / "alert_receipts.sqlite3"
    observed_notifier_db = Path(notifier_event_database).expanduser() if notifier_event_database else event_db
    monitor_domain = "system" if selected == "system" else f"gui/{uid if uid is not None else os.getuid()}"
    notifier_domain = f"gui/{uid if uid is not None else os.getuid()}"
    if is_frozen:
        monitor_args = (monitor_program, "--system-monitor-service" if selected == "system" else "--user-monitor-service")
        notifier_args = (notifier_program, "--user-notifier-service")
        application_mode = "frozen"
    else:
        monitor_args = (monitor_program, "-m", "mac_audit_agent.monitor", "--run", "--mode", "system-daemon" if selected == "system" else "user-notifier")
        notifier_args = (notifier_program, "-m", "mac_audit_agent.user_notifier", "--run")
        application_mode = execution_mode if execution_mode in {"source", "installed_package"} else "source"
    notifier_plist = home / "Library" / "LaunchAgents" / f"{NOTIFIER_LABEL}.plist"
    user_monitor_plist = home / "Library" / "LaunchAgents" / f"{MONITOR_LABEL}.plist"
    monitor_plist = SYSTEM_PLIST if selected == "system" else user_monitor_plist
    monitor_logs = SYSTEM_LOGS if selected == "system" else home / ".mac_audit_agent" / "logs"
    notifier_logs = home / "Library" / "Logs" / "MacAuditAgent"
    errors: list[str] = []
    if observed_notifier_db != event_db:
        errors.append("ALT001")
    if selected == "system" and actual == "none":
        errors.append("MON001")
    if selected == "system" and actual in {"user", "conflict"}:
        errors.append("MON005")
    aligned = observed_notifier_db == event_db
    conflicts = ("user",) if selected == "system" and actual in {"user", "conflict"} else (("system",) if selected == "user" and actual in {"system", "conflict"} else ())
    installed_services = (("system_monitor", "user_monitor") if actual == "conflict" else (("system_monitor",) if actual == "system" else (("user_monitor",) if actual == "user" else ())))
    working_directory = str(Path(monitor_program).parent if is_frozen else Path(__file__).resolve().parents[2])
    return RuntimeTopology(
        selected_monitor_mode=selected,
        requested_monitor_mode=selected,
        effective_monitor_mode=actual if actual != "none" else selected,
        actual_installed_monitor_mode=actual,
        installed_monitor_services=installed_services,
        conflicting_monitor_modes=conflicts,
        canonical_event_database=str(event_db),
        settings_storage_database=str(settings_db),
        alert_trace_database=str(receipt_db),
        notifier_transport="readonly_sqlite_event_source+per_user_receipt_store" if selected == "system" else "shared_user_sqlite",
        notifier_event_database=str(observed_notifier_db),
        notifier_receipt_database=str(receipt_db),
        acknowledgement_store=str(receipt_db),
        receipt_producer="system_monitor" if selected == "system" else "user_monitor",
        receipt_consumer="user_notifier",
        process_executable=process_executable,
        service_executable=monitor_program,
        notifier_executable=notifier_program,
        monitor_program_arguments=monitor_args,
        notifier_program_arguments=notifier_args,
        application_mode=application_mode,
        service_execution_mode=application_mode,
        monitor_launchctl_domain=monitor_domain,
        notifier_launchctl_domain=notifier_domain,
        monitor_service_label=MONITOR_LABEL,
        notifier_service_label=NOTIFIER_LABEL,
        working_directory=working_directory,
        effective_settings_version=_state_value(settings_db, "settings_version"),
        expected_event_db_owner="root" if selected == "system" else "current user",
        expected_event_db_group="admin" if selected == "system" else "staff",
        expected_event_db_mode="0640" if selected == "system" else "0600",
        expected_settings_owner="current user",
        expected_settings_mode="0600",
        monitor_requires_elevated_privileges=selected == "system",
        notifier_requires_elevated_privileges=False,
        executable_architecture=platform.machine(),
        build_id=current_git_commit(Path(__file__).resolve().parents[2]),
        application_version=APP_VERSION,
        monitor_plist_path=str(monitor_plist),
        notifier_plist_path=str(notifier_plist),
        monitor_stdout_path=str(monitor_logs / "background_monitor.stdout.log"),
        monitor_stderr_path=str(monitor_logs / "background_monitor.stderr.log"),
        notifier_stdout_path=str(notifier_logs / "user_notifier.stdout.log"),
        notifier_stderr_path=str(notifier_logs / "user_notifier.stderr.log"),
        aligned=aligned,
        error_codes=tuple(errors),
    )


def _normalize_mode(value: str) -> MonitorMode:
    return "system" if str(value).strip().lower() in {"system", "protected", "system-daemon"} else "user"


def _state_value(path: Path, key: str) -> str:
    try:
        if not path.exists():
            return ""
        uri = "file:{}?mode=ro".format(path.resolve(strict=False).as_posix())
        with sqlite3.connect(uri, uri=True) as connection:
            row = connection.execute("SELECT value FROM background_monitor_state WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else ""
    except sqlite3.Error:
        return ""


def _valid_plist(path: Path) -> bool:
    try:
        payload = plistlib.loads(path.read_bytes())
        return bool(payload.get("Label") == MONITOR_LABEL and payload.get("ProgramArguments"))
    except (OSError, ValueError, TypeError):
        return False


def _installed_mode(home: Path) -> str:
    system = _valid_plist(SYSTEM_PLIST)
    user = _valid_plist(home / "Library" / "LaunchAgents" / f"{MONITOR_LABEL}.plist")
    if system and user:
        return "conflict"
    if system:
        return "system"
    if user:
        return "user"
    return "none"


__all__ = ["RuntimeHealth", "RuntimeTopology", "evaluate_runtime_health", "resolve_runtime_topology", "user_settings_db"]
