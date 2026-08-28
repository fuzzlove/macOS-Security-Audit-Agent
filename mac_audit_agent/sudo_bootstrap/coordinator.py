from __future__ import annotations

import os
import platform
import plistlib
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .identity import InvokingUser
from .result import BootstrapErrorCode, BootstrapResult

DAEMON_LABEL = "com.mac-audit-agent.monitor"
AGENT_LABEL = "com.mac-audit-agent.user-notifier"
WATCHDOG_LABEL = "com.mac-audit-agent.service-watchdog"
SENSOR_HEALTH_LABEL = "com.mac-audit-agent.sensor-health"


def _source_is_user_writable(root: Path) -> bool:
    info = root.stat()
    return info.st_uid != 0 or bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def service_status(user: InvokingUser | None) -> dict[str, Any]:
    """Resolve live status without treating plist presence as health."""
    from mac_audit_agent.protection.status import resolve_active_protection_status

    home = user.home_directory if user else None
    status = resolve_active_protection_status(home=home).to_dict()
    daemon = status.get("system_daemon", {})
    agent = status.get("user_notifier", {})
    daemon_age = daemon.get("heartbeat_age_seconds")
    heartbeat_fresh = bool(daemon.get("running")) and isinstance(daemon_age, (int, float)) and daemon_age <= 90
    return {
        "schema_version": 1,
        "effective_uid": os.geteuid(),
        "invoking_user": user.to_dict() if user else None,
        "system_daemon": daemon,
        "user_agent": agent,
        "heartbeat_fresh": heartbeat_fresh,
        "ipc_connected": bool(status.get("ipc_connected", False)),
        "overall_status": status.get("status", "unknown"),
        "raw_status": status,
    }


def remove_service_registrations(user: InvokingUser) -> BootstrapResult:
    """Deregister exact MSAA jobs and retain recoverable plist backups."""
    result = BootstrapResult(invoked_through_sudo=user.source == "sudo", invoking_user=user.to_dict(), safe_to_continue_gui=False)
    targets = (
        ("system", DAEMON_LABEL, Path("/Library/LaunchDaemons") / f"{DAEMON_LABEL}.plist", BootstrapErrorCode.DAEMON_REGISTRATION_FAILED.value),
        ("system", WATCHDOG_LABEL, Path("/Library/LaunchDaemons") / f"{WATCHDOG_LABEL}.plist", BootstrapErrorCode.DAEMON_REGISTRATION_FAILED.value),
        ("system", SENSOR_HEALTH_LABEL, Path("/Library/LaunchDaemons") / f"{SENSOR_HEALTH_LABEL}.plist", BootstrapErrorCode.DAEMON_REGISTRATION_FAILED.value),
        (f"gui/{user.uid}", AGENT_LABEL, user.home_directory / "Library/LaunchAgents" / f"{AGENT_LABEL}.plist", BootstrapErrorCode.AGENT_INSTALL_FAILED.value),
        (f"gui/{user.uid}", DAEMON_LABEL, user.home_directory / "Library/LaunchAgents" / f"{DAEMON_LABEL}.plist", BootstrapErrorCode.AGENT_INSTALL_FAILED.value),
    )
    failures = 0
    backups: list[str] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for domain, label, plist, error_code in targets:
        command = ["/bin/launchctl", "bootout", domain, str(plist)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
        detail = (completed.stderr or completed.stdout).strip()
        absent_path_result = completed.returncode == 5 and not plist.exists()
        if completed.returncode not in {0, 3, 36, 113} and not absent_path_result and "could not find" not in detail.lower() and "no such process" not in detail.lower():
            failures += 1
            result.add_error(error_code, "launchd registration removal failed", "service_removal", system_error=detail, operation=" ".join(command), domain=domain, label=label)
            continue
        if plist.exists():
            info = plist.lstat()
            expected_uid = 0 if domain == "system" else user.uid
            try:
                payload = plistlib.loads(plist.read_bytes()) if info.st_size <= 1024 * 1024 else {}
            except (OSError, ValueError, plistlib.InvalidFileException):
                payload = {}
            if (
                not stat.S_ISREG(info.st_mode)
                or plist.is_symlink()
                or info.st_uid != expected_uid
                or payload.get("Label") != label
            ):
                failures += 1
                result.add_error(error_code, "Refused to move an unverified, incorrectly owned, or mismatched plist.", "service_removal", domain=domain, label=label)
                continue
            backup = plist.with_name(f"{plist.name}.deregistered-{timestamp}.bak")
            try:
                plist.rename(backup)
                backups.append(str(backup))
            except OSError as exc:
                failures += 1
                result.add_error(error_code, "Could not preserve the deregistered plist backup.", "service_removal", system_error=str(exc), domain=domain, label=label)
    result.protected_runtime = {"registration_backups": backups, "runtime_and_data_preserved": True}
    result.overall_result = BootstrapErrorCode.OK.value if failures == 0 else BootstrapErrorCode.PARTIAL.value
    result.remediation_actions = [
        "RUNTIME_DATABASES_EVIDENCE_QUARANTINE_AND_LOGS_WERE_PRESERVED",
        "VALID_ACTIVATED_COMMERCIAL_LICENSE_REQUIRED_FOR_REREGISTRATION",
    ]
    return result


def run_root_bootstrap(user: InvokingUser, *, operation: str, developer_mode: bool, allow_unsigned_development_runtime: bool) -> BootstrapResult:
    result = BootstrapResult(invoked_through_sudo=user.source == "sudo", invoking_user=user.to_dict())
    result.python_runtimes = {
        "bootstrap_python": os.path.realpath(sys.executable),
        "bootstrap_python_version": platform.python_version(),
        "gui_python": os.path.realpath(sys.executable),
        "gui_python_version": platform.python_version(),
    }
    root = Path(__file__).resolve().parents[2]
    source_mode = (root / "pyproject.toml").is_file() and not getattr(sys, "frozen", False)
    unsafe_source = source_mode and _source_is_user_writable(root)
    development_exception = developer_mode and allow_unsigned_development_runtime
    result.protected_runtime = {"source": str(root), "source_mode": source_mode, "integrity_valid": False, "development_exception": development_exception, "path": ""}
    if unsafe_source and not development_exception:
        result.add_error(BootstrapErrorCode.UNSAFE_SOURCE_RUNTIME.value, "A root LaunchDaemon cannot execute this user-writable source checkout. Use a signed package, or explicitly authorize isolated development staging.", "protected_runtime", operation="validate installation source", safe_to_continue=True)
        result.remediation_actions.append("USE_SIGNED_PRODUCTION_RUNTIME_OR_EXPLICIT_DEVELOPMENT_STAGING")
        result.safe_to_continue_gui = True
        result.overall_result = BootstrapErrorCode.PARTIAL.value
        return result
    from mac_audit_agent.protection.installer import (
        ActiveProtectionInstallOptions,
        install_active_protection,
    )
    if operation in {"install", "repair", "restart", "bootstrap"}:
        options = ActiveProtectionInstallOptions(operation_kind="repair" if operation in {"repair", "restart", "bootstrap"} else "install", target_uid=user.uid)
        installed = install_active_protection(options)
        result.protected_runtime["path"] = installed.selected_runtimes.get("daemon", "")
        result.system_daemon = installed.verification.get("system_daemon", {}) if isinstance(installed.verification, dict) else {}
        result.user_agent = installed.verification.get("user_notifier", {}) if isinstance(installed.verification, dict) else {}
        if installed.status != "installed_running":
            result.add_error(BootstrapErrorCode.DAEMON_HEARTBEAT_STALE.value, installed.message, "service_bootstrap", operation=operation, domain="system", label=DAEMON_LABEL, safe_to_continue=True)
            result.remediation_actions.append(installed.recommended_action or "RUN_SERVICE_STATUS")
            result.overall_result = BootstrapErrorCode.PARTIAL.value
        else:
            result.overall_result = BootstrapErrorCode.OK.value
    live = service_status(user)
    result.system_daemon = live.get("system_daemon", result.system_daemon)
    result.user_agent = live.get("user_agent", result.user_agent)
    result.endpoint_security = {"installed": False, "approved": False, "connected": False, "approval_required": True}
    result.safe_to_continue_gui = True
    return result
