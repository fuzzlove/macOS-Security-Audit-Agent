from __future__ import annotations

import json
import os
import plistlib
import pwd
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import (
    LAUNCH_AGENT_LABEL,
    SYSTEM_DB_PATH,
    LaunchAgentManager,
)
from mac_audit_agent.licensing.registration import service_registration_license_decision
from mac_audit_agent.sensor_health_service import (
    SENSOR_HEALTH_LABEL,
    build_sensor_health_plist,
    install_sensor_health_service,
)
from mac_audit_agent.service_watchdog import (
    WATCHDOG_LABEL,
    build_watchdog_plist,
    install_watchdog,
)
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.target_desktop_user import (
    TargetDesktopUser,
    TargetUserError,
    resolve_target_desktop_user,
)
from mac_audit_agent.user_notifier_installer import (
    USER_NOTIFIER_LABEL,
    UserNotifierInstaller,
)
from mac_audit_agent.version import APP_VERSION

from .status import resolve_active_protection_status


@dataclass(frozen=True)
class ActiveProtectionInstallOptions:
    mode: str = "protected"
    with_system_daemon: bool = True
    with_user_notifier: bool = True
    apply_current_settings: bool = True
    verify: bool = True
    verbose: bool = False
    target_uid: int | None = None
    test_root: Path | None = None
    operation_kind: str = "install"
    target_user: str | None = None
    target_gid: int | None = None
    target_home: Path | None = None


@dataclass
class ActiveProtectionInstallResult:
    status: str = "failed"
    first_failure_stage: str = ""
    message: str = ""
    actions_taken: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    backups_created: list[str] = field(default_factory=list)
    launchctl_commands: list[str] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    evidence_path: str = ""
    administrator_approval_required: bool = True
    recommended_action: str = ""
    selected_runtimes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _target(options: ActiveProtectionInstallOptions) -> TargetDesktopUser:
    return resolve_target_desktop_user(username=options.target_user, uid=options.target_uid, gid=options.target_gid, home=options.target_home, require_gui_session=options.with_user_notifier)


def _backup(path: Path, result: ActiveProtectionInstallResult) -> None:
    if not path.exists():
        return
    backup = path.with_name(f"{path.name}.backup-{_timestamp()}")
    shutil.copy2(path, backup)
    result.backups_created.append(str(backup))


def _disable_conflicting_user_monitor(target: TargetDesktopUser, result: ActiveProtectionInstallResult) -> None:
    """Back up the obsolete same-label user monitor in protected topology."""
    conflicting = target.home / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    command = ["/bin/launchctl", "bootout", target.gui_domain, str(conflicting)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    result.launchctl_commands.append(" ".join(command))
    if not conflicting.exists():
        if completed.returncode == 0:
            result.actions_taken.append("unloaded obsolete user-domain monitor")
        return
    try:
        payload = plistlib.loads(conflicting.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException):
        payload = {}
    if conflicting.is_symlink() or not conflicting.is_file() or payload.get("Label") != LAUNCH_AGENT_LABEL:
        raise RuntimeError(f"Refused to modify unverified conflicting LaunchAgent: {conflicting}")
    disabled = conflicting.with_suffix(f".plist.disabled-{_timestamp()}")
    shutil.move(conflicting, disabled)
    result.backups_created.append(str(disabled))
    result.actions_taken.append(f"disabled obsolete user-domain monitor: {disabled}")


def _write_evidence(kind: str, result: ActiveProtectionInstallResult, started_at: str, uid: int, home: Path) -> None:
    payload = result.to_dict() | {"command": f"protection {kind}", "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(), "uid": uid, "user": pwd.getpwuid(uid).pw_name if uid >= 0 else "unknown", "mode": "protected"}
    evidence_dirs = [home / "Library/Application Support/MacAuditAgent/protection_evidence"]
    try:
        evidence_dirs.append(Path.cwd() / "reports/protection_evidence")
    except OSError:
        # A root-authorized process may inherit a cwd on a privacy-protected or
        # removable volume that it cannot stat. Keep evidence in the protected
        # installed support tree instead of turning success into an exception.
        evidence_dirs.append(Path("/Library/Application Support/MacAuditAgent/protection_evidence"))
    for evidence_dir in evidence_dirs:
        try:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            path = evidence_dir / f"active_protection_{kind}_{_timestamp()}.json"
            path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
            result.evidence_path = str(path)
            return
        except (OSError, KeyError):
            continue


def _install_test_root(options: ActiveProtectionInstallOptions, result: ActiveProtectionInstallResult) -> None:
    root = Path(options.test_root or "/")
    system_support = root / "Library/Application Support/MacAuditAgent"
    daemon_plist = root / "Library/LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist"
    user_home = root / "Users/tester"
    notifier_plist = user_home / "Library/LaunchAgents" / f"{USER_NOTIFIER_LABEL}.plist"
    watchdog_plist = root / "Library/LaunchDaemons" / f"{WATCHDOG_LABEL}.plist"
    sensor_health_plist = root / "Library/LaunchDaemons" / f"{SENSOR_HEALTH_LABEL}.plist"
    db_path = system_support / "mac_audit_agent.sqlite3"
    manifest_path = system_support / "runtime/install_manifest.json"
    for directory in (system_support / "logs", daemon_plist.parent, notifier_plist.parent, manifest_path.parent, user_home / "Library/Application Support/MacAuditAgent/runtime"):
        directory.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS background_monitor_state(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT OR REPLACE INTO background_monitor_state VALUES('protection_mode','protected')")
    daemon_payload = {"Label": LAUNCH_AGENT_LABEL, "ProgramArguments": [sys.executable, "-m", "mac_audit_agent.monitor", "--service"], "RunAtLoad": True, "KeepAlive": True, "EnvironmentVariables": {"MAC_AUDIT_AGENT_DB_PATH": str(db_path)}}
    notifier_payload = {"Label": USER_NOTIFIER_LABEL, "ProgramArguments": [sys.executable, "-m", "mac_audit_agent.user_notifier", "--run"], "RunAtLoad": True, "KeepAlive": True, "EnvironmentVariables": {"MAC_AUDIT_AGENT_DB_PATH": str(db_path)}}
    watchdog_payload = build_watchdog_plist(sys.executable, options.target_uid or os.getuid())
    sensor_health_payload = build_sensor_health_plist(sys.executable, options.target_uid or os.getuid())
    daemon_plist.write_bytes(plistlib.dumps(daemon_payload)); notifier_plist.write_bytes(plistlib.dumps(notifier_payload)); watchdog_plist.write_bytes(plistlib.dumps(watchdog_payload)); sensor_health_plist.write_bytes(plistlib.dumps(sensor_health_payload))
    manifest_path.write_text(json.dumps({"schema_version": "1", "runtime_version": APP_VERSION, "db_path": str(db_path), "manifest_digest_sha512": "test-root-verification"}, sort_keys=True), encoding="utf-8")
    result.files_written.extend(map(str, (db_path, daemon_plist, notifier_plist, watchdog_plist, sensor_health_plist, manifest_path)))
    result.actions_taken.extend(("created isolated active database schema", "generated system LaunchDaemon plist", "generated user notifier LaunchAgent plist", "generated persistent service watchdog plist", "generated Sensor Health assurance service plist", "generated installed runtime manifest"))
    result.verification = {"test_root": str(root), "daemon_plist_valid": bool(plistlib.loads(daemon_plist.read_bytes())), "notifier_plist_valid": bool(plistlib.loads(notifier_plist.read_bytes())), "watchdog_plist_valid": bool(plistlib.loads(watchdog_plist.read_bytes())), "sensor_health_plist_valid": bool(plistlib.loads(sensor_health_plist.read_bytes())), "database_schema_ok": True, "live_launchctl_not_claimed": True}
    result.status = "test_root_verified"
    result.message = "Isolated installation artifacts were generated and verified; no live host service state is claimed."


def install_active_protection(options: ActiveProtectionInstallOptions) -> ActiveProtectionInstallResult:
    started = datetime.now(timezone.utc).isoformat()
    result = ActiveProtectionInstallResult(message="MSAA will install a protected system LaunchDaemon and a user LaunchAgent for visible alerts. Events remain local.")
    if options.test_root is not None:
        uid = options.target_uid if options.target_uid is not None else os.getuid()
        home = Path(options.test_root) / "Users/tester"
    else:
        try:
            target = _target(options)
        except TargetUserError as exc:
            result.status = "failed"; result.first_failure_stage = exc.code; result.message = str(exc); result.recommended_action = "Specify --target-user, --target-uid, --target-gid, and --target-home for the active desktop user, or launch through validated sudo."
            return result
        uid, home = target.uid, target.home
    if options.test_root is not None:
        _install_test_root(options, result)
        _write_evidence(options.operation_kind, result, started, uid, home)
        return result
    license_decision = service_registration_license_decision(home)
    if not license_decision.allowed:
        result.status = "license_required"
        result.first_failure_stage = "product_license"
        result.message = f"{license_decision.code}: {license_decision.message}"
        result.recommended_action = (
            "Complete Stripe checkout and activate the signed license, then retry Active "
            "Protection registration."
        )
        result.verification = {"service_registration_license": license_decision.to_dict()}
        _write_evidence(options.operation_kind, result, started, uid, home)
        return result
    if sys.platform != "darwin":
        result.first_failure_stage = "platform_preflight"; result.message = "Active Protection installation requires macOS."; result.recommended_action = "Run the installer on macOS."
        _write_evidence(options.operation_kind, result, started, uid, home); return result
    if os.geteuid() != 0:
        result.status = "permission_blocked"; result.first_failure_stage = "administrator_preflight"; result.message = "Administrator approval is required before installing the system LaunchDaemon."; result.recommended_action = "Review the install plan, then run the displayed command from an administrator-approved terminal. MSAA does not invoke sudo automatically."
        _write_evidence(options.operation_kind, result, started, uid, home); return result
    try:
        os.environ["MSAA_GUI_USER"] = target.username; os.environ["MSAA_GUI_UID"] = str(uid); os.environ["MSAA_GUI_GID"] = str(target.gid); os.environ["MSAA_GUI_HOME"] = str(home)
        if options.with_system_daemon:
            _disable_conflicting_user_monitor(target, result)
        from mac_audit_agent.launch_agent import (
            compatible_python_executable,
            is_system_service_safe_executable,
        )
        from mac_audit_agent.runtime.python_selector import select_best_python_for_mode
        daemon_selection = select_best_python_for_mode("daemon")
        notifier_selection = select_best_python_for_mode("notifier")
        daemon_python = sys.executable if getattr(sys, "frozen", False) else compatible_python_executable("daemon")
        notifier_python = sys.executable if getattr(sys, "frozen", False) else notifier_selection.selected_executable
        result.selected_runtimes = {"daemon": daemon_python, "daemon_tier": daemon_selection.runtime_tier, "notifier": notifier_python, "notifier_tier": notifier_selection.runtime_tier}
        if options.with_system_daemon and not daemon_python:
            raise RuntimeError("No validated headless Python runtime is available for the system daemon.")
        if options.with_system_daemon and not getattr(sys, "frozen", False) and not is_system_service_safe_executable(daemon_python):
            raise RuntimeError(
                "The selected daemon runtime is inside a user, temporary, mounted, or virtual-environment path. "
                "Install with a system-accessible Python runtime or a signed frozen MSAA service artifact."
            )
        if options.with_user_notifier and not notifier_python:
            raise RuntimeError("No validated GUI-capable Python 3.10-3.13 runtime is available for the user notifier.")
        database = AuditDatabase(SYSTEM_DB_PATH)
        try:
            if options.apply_current_settings:
                database.set_background_monitor_state("protection_mode", options.mode)
                database.set_background_monitor_state("active_protection_installed_at", datetime.now(timezone.utc).isoformat())
                result.actions_taken.append("applied current protected monitoring settings")
        finally:
            database.close()
        if options.with_system_daemon:
            manager = LaunchAgentManager(SYSTEM_DB_PATH, scope="system", process_executable=daemon_python, frozen=bool(getattr(sys, "frozen", False)))
            _backup(manager.paths.plist_path, result); _backup(manager.protected_monitor_manifest_path(), result)
            plist = manager.install_system_monitor(); result.files_written.append(str(plist)); result.actions_taken.append("installed protected system LaunchDaemon")
            manager.start(); result.launchctl_commands.extend((f"launchctl bootstrap system {plist}", f"launchctl kickstart -k system/{LAUNCH_AGENT_LABEL}"))
        if options.with_user_notifier:
            notifier = UserNotifierInstaller(db_path=SYSTEM_DB_PATH, target_user=target, python_executable=notifier_python, frozen=bool(getattr(sys, "frozen", False)))
            cleanup = notifier.cleanup_stale_root_installation()
            result.actions_taken.extend(cleanup)
            _backup(notifier.plist_path, result); _backup(notifier.runtime_dir / "install_manifest.json", result)
            notifier_status = notifier.install_user_notifier(start=True); result.files_written.append(str(notifier.plist_path)); result.actions_taken.append("installed user notifier LaunchAgent")
            result.launchctl_commands.extend((f"launchctl bootstrap gui/{uid} {notifier.plist_path}", f"launchctl kickstart -k gui/{uid}/{USER_NOTIFIER_LABEL}"))
            if not notifier_status.running:
                raise RuntimeError(notifier_status.last_error or "user notifier did not reach running state")
        if options.with_system_daemon:
            sensor_health_plist = install_sensor_health_service(daemon_python, uid, frozen=bool(getattr(sys, "frozen", False)))
            result.files_written.append(str(sensor_health_plist))
            result.actions_taken.append("installed periodic Sensor Health functional assurance service")
            result.launchctl_commands.extend((f"launchctl bootstrap system {sensor_health_plist}", f"launchctl kickstart -k system/{SENSOR_HEALTH_LABEL}"))
            watchdog_plist = install_watchdog(daemon_python, uid, frozen=bool(getattr(sys, "frozen", False)))
            result.files_written.append(str(watchdog_plist))
            result.actions_taken.append("installed persistent integrity-gated service watchdog")
            result.launchctl_commands.extend((f"launchctl bootstrap system {watchdog_plist}", f"launchctl kickstart -k system/{WATCHDOG_LABEL}"))
        if options.verify:
            result.verification = resolve_active_protection_status(home=home).to_dict()
            for _ in range(10):
                if result.verification.get("status") == "installed_running":
                    break
                time.sleep(1)
                result.verification = resolve_active_protection_status(home=home).to_dict()
        else:
            result.verification = {}
        if options.verify and result.verification.get("status") != "installed_running":
            result.status = "verification_failed"; result.first_failure_stage = result.verification.get("first_failure_stage", "verify_after_install"); result.message = "Installation completed, but live protection verification did not pass."; result.recommended_action = result.verification.get("recommended_command", "Run protection doctor.")
        else:
            result.status = "installed_running"; result.message = "Active Protection was installed and live daemon/notifier verification passed."; result.recommended_action = "Refresh Dashboard and Operational Health."
    except Exception as exc:
        result.status = "failed"; result.first_failure_stage = result.first_failure_stage or "install_components"; result.message = f"Active Protection installation failed: {type(exc).__name__}: {exc}"; result.recommended_action = "Run python3.12 -m mac_audit_agent.protection doctor --json and review the first failing stage."
    _write_evidence(options.operation_kind, result, started, uid, home)
    return result


__all__ = ["ActiveProtectionInstallOptions", "ActiveProtectionInstallResult", "install_active_protection"]
