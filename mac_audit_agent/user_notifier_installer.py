from __future__ import annotations

import json
import os
import plistlib
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import (
    LAUNCHCTL_BIN,
    MAC_AUDIT_AGENT_ENV_DB_PATH,
    PLUTIL_BIN,
    compatible_python_executable,
    default_monitor_db_path,
    project_root,
    user_launchctl_uid,
)
from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.runtime.topology import resolve_runtime_topology
from mac_audit_agent.target_desktop_user import (
    TargetDesktopUser,
    resolve_target_desktop_user,
)
from mac_audit_agent.version import APP_VERSION, current_git_commit

USER_NOTIFIER_LABEL = "com.mac-audit-agent.user-notifier"
USER_NOTIFIER_STDOUT = "user_notifier.stdout.log"
USER_NOTIFIER_STDERR = "user_notifier.stderr.log"
MAC_AUDIT_AGENT_SETTINGS_PATH = "MAC_AUDIT_AGENT_SETTINGS_PATH"
MAC_AUDIT_AGENT_ALERT_TRACE_PATH = "MAC_AUDIT_AGENT_ALERT_TRACE_PATH"
PID_RE = re.compile(r"\bpid = (\d+)\b")
ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+00:00|Z)?")


@dataclass
class UserNotifierStatus:
    label: str = USER_NOTIFIER_LABEL
    install_status: str = "unknown"
    plist_path: str = ""
    plist_exists: bool = False
    plist_valid: bool = False
    loaded: bool = False
    running: bool = False
    process_pid: int | None = None
    logs_writable: bool = False
    launchctl_domain: str = ""
    program_arguments: list[str] | None = None
    working_directory: str = ""
    pythonpath: str = ""
    db_path: str = ""
    heartbeat_db_path: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    last_error: str = ""
    last_bootstrap_result: str = ""
    last_bootout_result: str = ""
    runtime_manifest_path: str = ""
    runtime_manifest_exists: bool = False
    launchctl_print: str = ""
    last_exit_status: str = ""
    stderr_tail: str = ""
    stdout_tail: str = ""
    live_launchctl_loaded: bool = False
    live_launchctl_running: bool = False
    live_process_pid: int | None = None
    active_db_heartbeat: str = ""
    active_db_heartbeat_age_seconds: float | None = None
    stdout_tail_latest_timestamp: str = ""
    stderr_tail_latest_timestamp: str = ""
    historical_stdout_heartbeat_detected: bool = False
    stale_log_evidence: bool = False
    status_source: str = "live_launchctl_process_plist"
    target_username: str = ""
    target_uid: int | None = None
    target_home: str = ""
    process_uid: int | None = None
    graphical_session_available: bool = False
    heartbeat_fresh: bool = False
    error_code: str = ""
    source_database_readable: bool = False
    source_database_integrity: str = "unknown"
    source_database_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class UserNotifierInstaller:
    def __init__(
        self,
        *,
        db_path: Path | None = None,
        home: Path | None = None,
        runner=None,
        python_executable: str | None = None,
        frozen: bool | None = None,
        target_user: TargetDesktopUser | None = None,
    ) -> None:
        if target_user is None:
            if runner is not None and home is not None and os.geteuid() != 0:
                # Explicit dependency-injected test/status roots never enter the
                # privileged production installer path.
                record = pwd.getpwuid(user_launchctl_uid())
                target_user = TargetDesktopUser(record.pw_name, record.pw_uid, record.pw_gid, Path(home), f"gui/{record.pw_uid}", False)
            elif os.geteuid() == 0:
                target_user = resolve_target_desktop_user(home=home, require_gui_session=True)
            else:
                target_user = resolve_target_desktop_user(uid=user_launchctl_uid(), home=home, require_gui_session=False)
        self.target_user = target_user
        self.uid = target_user.uid
        self.user = pwd.getpwuid(self.uid)
        self.home = target_user.home
        if self.home == Path("/var/root"):
            raise ValueError("NOTIFIER_TARGET_USER_IS_ROOT: notifier home cannot be /var/root")
        self.runner = runner or subprocess.run
        self.python_executable = python_executable or _python_executable()
        default_settings = self.home / ".mac_audit_agent.sqlite3"
        preliminary = resolve_runtime_topology(default_settings, uid=self.uid, home=self.home)
        self.settings_db_path = Path(db_path).expanduser() if db_path is not None and preliminary.selected_monitor_mode == "user" and not default_settings.exists() else default_settings
        self.topology = resolve_runtime_topology(
            self.settings_db_path,
            notifier_event_database=db_path,
            frozen=frozen,
            executable=self.python_executable,
            notifier_executable=self.python_executable,
            uid=self.uid,
            home=self.home,
        )
        self.db_path = Path(db_path or self.topology.canonical_event_database).expanduser()
        self.launch_agents_dir = self.home / "Library" / "LaunchAgents"
        self.log_dir = self.home / "Library" / "Logs" / "MacAuditAgent"
        self.app_support_dir = self.home / "Library" / "Application Support" / "MacAuditAgent"
        self.runtime_dir = self.app_support_dir / "runtime"
        self.runtime_package_dir = self.runtime_dir / "mac_audit_agent"
        self.plist_path = self.launch_agents_dir / f"{USER_NOTIFIER_LABEL}.plist"
        self.stdout_path = self.log_dir / USER_NOTIFIER_STDOUT
        self.stderr_path = self.log_dir / USER_NOTIFIER_STDERR

    @property
    def launchctl_domain(self) -> str:
        return self.target_user.gui_domain

    def _require_registration_license(self) -> None:
        # Custom runners are reserved for isolated tests; real launchd and
        # filesystem mutations must verify the target user's signed license.
        if self.runner is subprocess.run:
            from mac_audit_agent.licensing.registration import (
                require_service_registration_license,
            )

            require_service_registration_license(self.home)

    def cleanup_stale_root_installation(self) -> list[str]:
        """Remove only the exact legacy root notifier registration and plist."""
        actions: list[str] = []
        stale = Path("/var/root/Library/LaunchAgents") / f"{USER_NOTIFIER_LABEL}.plist"
        evidence = self.log_dir / "stale_root_notifier_cleanup.json"
        observations: list[dict[str, Any]] = []
        for domain in ("system", "gui/0"):
            probe = self._run([LAUNCHCTL_BIN, "print", f"{domain}/{USER_NOTIFIER_LABEL}"], check=False)
            if probe.returncode == 0:
                observations.append({"domain": domain, "detail": _result_text(probe)[-2000:]})
                removed = self._run([LAUNCHCTL_BIN, "bootout", f"{domain}/{USER_NOTIFIER_LABEL}"], check=False)
                if removed.returncode == 0:
                    actions.append(f"STALE_ROOT_NOTIFIER_REMOVED: {domain}/{USER_NOTIFIER_LABEL}")
        if stale.exists():
            info = stale.lstat()
            owned_by_msaa = False
            if stat.S_ISREG(info.st_mode) and not stale.is_symlink() and info.st_size <= 1024 * 1024:
                try:
                    payload = plistlib.loads(stale.read_bytes())
                    arguments = payload.get("ProgramArguments", [])
                    owned_by_msaa = payload.get("Label") == USER_NOTIFIER_LABEL and isinstance(arguments, list) and "mac_audit_agent.user_notifier" in arguments
                except (OSError, ValueError, plistlib.InvalidFileException):
                    owned_by_msaa = False
            if owned_by_msaa:
                observations.append({"plist": str(stale), "owner_uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)), "validated_label": USER_NOTIFIER_LABEL})
                stale.unlink()
                actions.append(f"STALE_ROOT_NOTIFIER_REMOVED: {stale}")
        if observations:
            self.ensure_directories()
            evidence.write_text(json.dumps({"timestamp": utc_now_iso(), "observations": observations, "actions": actions}, indent=2, sort_keys=True), encoding="utf-8")
            self._chown_user_path(evidence)
        return actions

    def ensure_directories(self) -> None:
        for directory in [self.launch_agents_dir, self.log_dir, self.app_support_dir, self.runtime_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700 if directory in {self.log_dir, self.app_support_dir} else 0o755)
            except OSError:
                pass
            self._chown_user_path(directory)
        self.ensure_receipt_store_permissions()

    def ensure_receipt_store_permissions(self) -> None:
        receipt = Path(self.topology.alert_trace_database).expanduser()
        for candidate in (receipt, Path(f"{receipt}-wal"), Path(f"{receipt}-shm")):
            try:
                info = candidate.lstat()
                if candidate.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid:
                    continue
                candidate.chmod(0o600)
            except OSError:
                continue

    def install_user_notifier(self, *, run_at_load: bool = True, keep_alive: bool = True, start: bool = True) -> UserNotifierStatus:
        self._require_registration_license()
        self.ensure_directories()
        self._install_runtime_files()
        self.settings_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._chown_user_path(self.settings_db_path.parent)
        payload = self.build_plist(run_at_load=run_at_load, keep_alive=keep_alive)
        self.plist_path.write_bytes(plistlib.dumps(payload))
        os.chmod(self.plist_path, 0o644)
        self._chown_user_path(self.plist_path)
        self._run([PLUTIL_BIN, "-lint", str(self.plist_path)])
        status = self.get_user_notifier_status()
        self._persist_status(status)
        # A prior loaded job may still report its old non-zero exit status here.
        # The newly written plist/runtime are the install preconditions; stale
        # launchd state must be booted out before live health is evaluated.
        if not status.plist_valid:
            raise RuntimeError(status.last_error)
        if start:
            return self.load_user_notifier()
        return status

    def uninstall_user_notifier(self) -> UserNotifierStatus:
        bootout = self.unload_user_notifier()
        if self.plist_path.exists():
            self.plist_path.unlink()
        status = self.get_user_notifier_status()
        status.last_bootout_result = bootout.last_bootout_result
        self._persist_status(status)
        return status

    def load_user_notifier(self) -> UserNotifierStatus:
        self._require_registration_license()
        staged = self.get_user_notifier_status()
        if not staged.plist_valid:
            raise RuntimeError(staged.last_error or "User Alert Agent plist is invalid.")
        if self.topology.application_mode != "frozen" and not (self.runtime_package_dir / "user_notifier.py").is_file():
            raise RuntimeError(f"Staged User Alert Agent module is missing: {self.runtime_package_dir / 'user_notifier.py'}")
        self._run([LAUNCHCTL_BIN, "bootout", self.launchctl_domain, str(self.plist_path)], check=False)
        result = self._run([LAUNCHCTL_BIN, "bootstrap", self.launchctl_domain, str(self.plist_path)], check=False)
        status = self.get_user_notifier_status()
        detail = _result_text(result)
        status.last_bootstrap_result = detail
        if result.returncode != 0 and "service already loaded" not in detail.lower() and "already bootstrapped" not in detail.lower():
            status.last_error = _failure(
                "launchctl bootstrap failed",
                [LAUNCHCTL_BIN, "bootstrap", self.launchctl_domain, str(self.plist_path)],
                detail,
                "Run Repair User Alert Agent. Verify the plist is owned by the current user and launchctl domain is gui/<uid>.",
            )
            status.install_status = "broken"
            self._persist_status(status)
            return status
        self._run([LAUNCHCTL_BIN, "enable", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"], check=False)
        self._run([LAUNCHCTL_BIN, "kickstart", "-k", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"], check=False)
        status = self.get_user_notifier_status()
        self._persist_status(status)
        return status

    def unload_user_notifier(self) -> UserNotifierStatus:
        result = self._run([LAUNCHCTL_BIN, "bootout", self.launchctl_domain, str(self.plist_path)], check=False)
        status = self.get_user_notifier_status()
        status.last_bootout_result = _result_text(result)
        self._persist_status(status)
        return status

    def restart_user_notifier(self) -> UserNotifierStatus:
        self._require_registration_license()
        self.unload_user_notifier()
        return self.load_user_notifier()

    def repair_user_notifier(self) -> UserNotifierStatus:
        self._require_registration_license()
        self.unload_user_notifier()
        if self.plist_path.exists():
            self.plist_path.unlink()
        return self.install_user_notifier(start=True)

    def verify_user_notifier(self, *, raise_on_error: bool = False) -> UserNotifierStatus:
        status = self.get_user_notifier_status()
        if status.install_status in {"missing", "broken"} and raise_on_error:
            raise RuntimeError(status.last_error or f"User Alert Agent is {status.install_status}.")
        return status

    def get_user_notifier_status(self) -> UserNotifierStatus:
        status = UserNotifierStatus(
            plist_path=str(self.plist_path),
            plist_exists=self.plist_path.exists(),
            launchctl_domain=self.launchctl_domain,
            stdout_path=str(self.stdout_path),
            stderr_path=str(self.stderr_path),
            logs_writable=os.access(self.log_dir, os.W_OK) if self.log_dir.exists() else False,
            runtime_manifest_path=str(self.runtime_dir / "install_manifest.json"),
            runtime_manifest_exists=(self.runtime_dir / "install_manifest.json").exists(),
            target_username=self.target_user.username,
            target_uid=self.target_user.uid,
            target_home=str(self.target_user.home),
            graphical_session_available=self.target_user.console_session_active,
        )
        if not self.plist_path.exists():
            status.install_status = "missing"
            status.last_error = "Events are being collected, but the user alert agent is not running."
            return status
        try:
            payload = plistlib.loads(self.plist_path.read_bytes())
            status.plist_valid = True
            status.program_arguments = list(payload.get("ProgramArguments", []))
            status.working_directory = str(payload.get("WorkingDirectory", ""))
            env = payload.get("EnvironmentVariables", {}) if isinstance(payload.get("EnvironmentVariables", {}), dict) else {}
            status.pythonpath = str(env.get("PYTHONPATH", ""))
            status.db_path = str(env.get(MAC_AUDIT_AGENT_ENV_DB_PATH, ""))
            status.heartbeat_db_path = str(env.get(MAC_AUDIT_AGENT_ALERT_TRACE_PATH, ""))
            if payload.get("Label") != USER_NOTIFIER_LABEL:
                raise ValueError(f"plist Label must be {USER_NOTIFIER_LABEL}, got {payload.get('Label')}")
            if not status.program_arguments:
                raise ValueError("plist ProgramArguments is empty")
            mode = stat.S_IMODE(self.plist_path.stat().st_mode)
            if mode != 0o644:
                raise ValueError(f"plist mode is {oct(mode)}, expected 0o644")
            if self.plist_path.stat().st_uid != self.uid:
                status.error_code = "NOTIFIER_PLIST_WRONG_OWNER"
                raise ValueError(f"plist owner uid is {self.plist_path.stat().st_uid}, expected {self.uid}")
            if self.plist_path.parent != self.target_user.home / "Library/LaunchAgents":
                status.error_code = "NOTIFIER_PLIST_WRONG_LOCATION"
                raise ValueError("notifier plist is outside the target user's LaunchAgents directory")
        except Exception as exc:
            status.install_status = "broken"
            status.last_error = _failure(
                "plist invalid",
                [PLUTIL_BIN, "-lint", str(self.plist_path)],
                str(exc),
                "Run Repair User Alert Agent to rewrite the canonical user LaunchAgent plist.",
            )
            return status
        result = self._run([LAUNCHCTL_BIN, "print", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"], check=False)
        status.launchctl_print = (result.stdout or result.stderr or "")[-4000:]
        status.loaded = result.returncode == 0
        output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        pid_match = PID_RE.search(result.stdout or "")
        if pid_match:
            status.process_pid = int(pid_match.group(1))
            status.process_uid = self._process_uid(status.process_pid)
        status.running = status.loaded and ("state = running" in output or status.process_pid is not None)
        if status.running and status.process_uid not in {None, self.uid}:
            status.running = False
            status.install_status = "broken"
            status.error_code = "NOTIFIER_WRONG_LAUNCHD_DOMAIN"
            status.last_error = f"Notifier process UID {status.process_uid} does not match target UID {self.uid}."
        if status.loaded:
            status.install_status = "loaded"
            status.last_exit_status = _extract_last_exit_status(status.launchctl_print)
            if not status.running and status.last_exit_status:
                status.install_status = "broken"
        else:
            status.install_status = "unloaded"
            status.last_error = _failure(
                "launchctl print did not find the user alert agent",
                [LAUNCHCTL_BIN, "print", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"],
                _result_text(result),
                "Run Start or Repair User Alert Agent. The service must be loaded in gui/<uid>, not as a system LaunchDaemon.",
            )
        status.stderr_tail = _tail_file(self.stderr_path)
        status.stdout_tail = _tail_file(self.stdout_path)
        status.live_launchctl_loaded = status.loaded
        status.live_launchctl_running = status.running
        status.live_process_pid = status.process_pid
        heartbeat_database = status.heartbeat_db_path or status.db_path
        status.active_db_heartbeat = _read_active_db_heartbeat(Path(heartbeat_database)) if heartbeat_database else ""
        status.active_db_heartbeat_age_seconds = _heartbeat_age_seconds(status.active_db_heartbeat)
        status.heartbeat_fresh = status.active_db_heartbeat_age_seconds is not None and status.active_db_heartbeat_age_seconds <= 90
        status.stdout_tail_latest_timestamp = _latest_timestamp(status.stdout_tail)
        status.stderr_tail_latest_timestamp = _latest_timestamp(status.stderr_tail)
        status.historical_stdout_heartbeat_detected = "heartbeat" in status.stdout_tail.lower()
        status.stale_log_evidence = bool(status.stdout_tail_latest_timestamp and (not status.active_db_heartbeat or status.stdout_tail_latest_timestamp != status.active_db_heartbeat))
        if status.db_path:
            readable, integrity, error = _probe_notifier_source_database(Path(status.db_path))
            status.source_database_readable = readable
            status.source_database_integrity = integrity
            status.source_database_error = error
            if not readable and integrity not in {"missing", "schema_missing"}:
                status.install_status = "broken"
                status.error_code = "NOTIFIER_SOURCE_DATABASE_UNREADABLE"
                status.last_error = error
        if status.install_status == "broken" and not status.last_error:
            status.error_code = "NOTIFIER_EXITED_EARLY"
            status.last_error = _failure(
                "user alert agent is loaded but not running",
                status.program_arguments or [self.python_executable, "-m", "mac_audit_agent.user_notifier", "--run"],
                f"launchctl state is not running; last exit status: {status.last_exit_status or 'unknown'}\n\nStderr/log tail:\n{status.stderr_tail[-2000:]}",
                "Run Repair User Alert Agent to rewrite the LaunchAgent with a compatible Python runtime, then restart it.",
            )
        status.status_source = "live_launchctl_process_plist"
        return status

    def _process_uid(self, pid: int) -> int | None:
        try:
            result = self._run(["/bin/ps", "-o", "uid=", "-p", str(pid)], check=False)
        except OSError:
            return None
        text = (result.stdout or "").strip()
        return int(text) if text.isdigit() else None

    def build_plist(self, *, run_at_load: bool = True, keep_alive: bool = True) -> dict[str, Any]:
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            MAC_AUDIT_AGENT_ENV_DB_PATH: str(self.db_path),
            MAC_AUDIT_AGENT_SETTINGS_PATH: self.topology.settings_storage_database,
            MAC_AUDIT_AGENT_ALERT_TRACE_PATH: self.topology.alert_trace_database,
            "MAC_AUDIT_AGENT_MONITOR_ROLE": "user-notifier",
            "MSAA_RUNTIME_TOPOLOGY": self.topology.notifier_transport,
        }
        return {
            "Label": USER_NOTIFIER_LABEL,
            "ProgramArguments": list(self.topology.notifier_program_arguments),
            "RunAtLoad": bool(run_at_load),
            "KeepAlive": bool(keep_alive),
            # Source-mode notifier imports only from its staged, user-owned runtime.
            # It must not depend on the checkout, caller cwd, PYTHONPATH, or site cwd.
            "WorkingDirectory": str(Path(self.python_executable).parent if self.topology.application_mode == "frozen" else self.runtime_dir),
            "EnvironmentVariables": environment,
            "StandardOutPath": str(self.stdout_path),
            "StandardErrorPath": str(self.stderr_path),
            "ProcessType": "Interactive",
        }

    def _install_runtime_files(self) -> None:
        if self.topology.application_mode != "frozen":
            source_package = project_root() / "mac_audit_agent"
            entry_module = source_package / "user_notifier.py"
            if not entry_module.is_file():
                raise FileNotFoundError(f"User notifier source module is missing: {entry_module}")
            self._reset_runtime_package_dir()
            shutil.copytree(
                source_package,
                self.runtime_package_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
                copy_function=shutil.copyfile,
            )
            staged_entry = self.runtime_package_dir / "user_notifier.py"
            if not staged_entry.is_file():
                raise RuntimeError(f"User notifier staging did not create {staged_entry}")
        self._write_runtime_manifest()
        self._chown_user_path(self.runtime_dir, recursive=True)

    def _reset_runtime_package_dir(self) -> None:
        if not self.runtime_package_dir.exists():
            return
        for cache_dir in sorted(self.runtime_package_dir.rglob("__pycache__"), reverse=True):
            shutil.rmtree(cache_dir, ignore_errors=True)
        for path in sorted(self.runtime_package_dir.rglob("*"), reverse=True):
            try:
                path.chmod(0o755 if path.is_dir() else 0o644)
            except OSError:
                pass
        try:
            self.runtime_package_dir.chmod(0o755)
        except OSError:
            pass
        shutil.rmtree(self.runtime_package_dir, ignore_errors=True)

    def _write_runtime_manifest(self) -> None:
        manifest = {
            "schema": "UserNotifierIntegrityManifest",
            "installed_at": utc_now_iso(),
            "install_mode": "user_notifier",
            "runtime_path": str(self.runtime_dir),
            "runtime_package_path": str(self.runtime_package_dir),
            "runtime_entry_module": str(self.runtime_package_dir / "user_notifier.py"),
            "plist_path": str(self.plist_path),
            "db_path": str(self.db_path),
            "settings_path": self.topology.settings_storage_database,
            "alert_trace_path": self.topology.alert_trace_database,
            "settings_version": "",
            "program_arguments": list(self.topology.notifier_program_arguments),
            "working_directory": str(Path(self.python_executable).parent if self.topology.application_mode == "frozen" else self.runtime_dir),
            "pythonpath": "",
            "application_mode": self.topology.application_mode,
            "launchctl_domain": self.topology.notifier_launchctl_domain,
            "owner_expected": self.user.pw_name,
            "permissions_expected": "0644",
            "package_version": APP_VERSION,
            "app_version": APP_VERSION,
            "git_commit": current_git_commit(),
        }
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        (self.runtime_dir / "install_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        self._chown_user_path(self.runtime_dir / "install_manifest.json")

    def _persist_status(self, status: UserNotifierStatus) -> None:
        try:
            self.settings_db_path.parent.mkdir(parents=True, exist_ok=True)
            self._chown_user_path(self.settings_db_path.parent)
            with sqlite3.connect(str(self.settings_db_path)) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS background_monitor_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                values = {
                    "user_notifier_install_status": status.install_status,
                    "user_notifier_loaded": "1" if status.loaded else "0",
                    "user_notifier_running": "1" if status.running else "0",
                    "user_notifier_program_arguments": " ".join(status.program_arguments or []),
                    "user_notifier_launchctl_domain": status.launchctl_domain,
                    "user_notifier_db_path": status.db_path,
                    "user_notifier_stdout_path": status.stdout_path,
                    "user_notifier_stderr_path": status.stderr_path,
                    "user_notifier_last_error": "" if status.running else status.last_error,
                    "notifier_last_error": "" if status.running else status.last_error,
                    "notification_status": "User Alert Agent installed and running." if status.running else f"User Alert Agent repair required: {status.last_error}",
                }
                conn.executemany(
                    "INSERT OR REPLACE INTO background_monitor_state(key, value) VALUES (?, ?)",
                    [(key, str(value)) for key, value in values.items()],
                )
            self._chown_user_path(self.settings_db_path)
        except sqlite3.Error:
            pass

    def _chown_user_path(self, path: Path, *, recursive: bool = False) -> None:
        try:
            os.chown(path, self.uid, self.user.pw_gid)
        except OSError:
            pass
        if not recursive or not path.is_dir():
            return
        for child in path.rglob("*"):
            try:
                os.chown(child, self.uid, self.user.pw_gid)
            except OSError:
                pass

    def _run(self, command: list[str], *, check: bool = True):
        result = self.runner(command, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(_failure("command failed", command, _result_text(result), "Run Repair User Alert Agent or inspect User Alert Agent Diagnostics."))
        return result


def _python_executable() -> str:
    return compatible_python_executable("notifier")


def _result_text(result) -> str:
    return (result.stderr or result.stdout or f"exit code {result.returncode}").strip()


def _format_command(command: list[str]) -> str:
    return " ".join(command)


def _failure(cause: str, command: list[str], detail: str, fix: str) -> str:
    return f"{cause}\ncommand: {_format_command(command)}\ndetail: {detail or 'none'}\nrecommended fix: {fix}"


def _tail_file(path: Path, max_chars: int = 4000) -> str:
    try:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[-max_chars:]
    except OSError:
        return ""


def _read_active_db_heartbeat(db_path: Path) -> str:
    try:
        if not db_path.exists():
            return ""
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT value FROM background_monitor_state WHERE key IN ('user_notifier_heartbeat', 'notifier_heartbeat') ORDER BY CASE key WHEN 'user_notifier_heartbeat' THEN 0 ELSE 1 END LIMIT 1"
            ).fetchone()
        return str(row[0]) if row and row[0] else ""
    except sqlite3.Error:
        return ""


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _heartbeat_age_seconds(value: str) -> float | None:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds())


def _latest_timestamp(text: str) -> str:
    matches = ISO_TS_RE.findall(text or "")
    return matches[-1].replace("Z", "+00:00") if matches else ""


def _extract_last_exit_status(text: str) -> str:
    for pattern in [r"last exit code = ([^\n]+)", r"last exit status = ([^\n]+)", r"exit status = ([^\n]+)"]:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def install_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).install_user_notifier(**_action_kwargs(kwargs))


def uninstall_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).uninstall_user_notifier()


def load_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).load_user_notifier()


def unload_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).unload_user_notifier()


def restart_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).restart_user_notifier()


def repair_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).repair_user_notifier()


def get_user_notifier_status(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).get_user_notifier_status()


def verify_user_notifier(**kwargs) -> UserNotifierStatus:
    return UserNotifierInstaller(**_installer_kwargs(kwargs)).verify_user_notifier()


def update_db_notifier_status(db, status: UserNotifierStatus) -> None:
    db.set_background_monitor_state("user_notifier_install_status", status.install_status)
    db.set_background_monitor_state("user_notifier_launch_agent_label", status.label)
    db.set_background_monitor_state("user_notifier_plist_path", status.plist_path)
    db.set_background_monitor_state("user_notifier_loaded", "1" if status.loaded else "0")
    db.set_background_monitor_state("user_notifier_running", "1" if status.running else "0")
    db.set_background_monitor_state("user_notifier_launchctl_domain", status.launchctl_domain)
    db.set_background_monitor_state("user_notifier_program_arguments", " ".join(status.program_arguments or []))
    db.set_background_monitor_state("user_notifier_db_path", status.db_path)
    db.set_background_monitor_state("user_notifier_stdout_path", status.stdout_path)
    db.set_background_monitor_state("user_notifier_stderr_path", status.stderr_path)
    db.set_background_monitor_state("user_notifier_last_error", status.last_error)
    db.set_background_monitor_state("user_notifier_status_source", status.status_source)
    db.set_background_monitor_state("user_notifier_active_db_heartbeat", status.active_db_heartbeat)
    db.set_background_monitor_state("user_notifier_active_db_heartbeat_age_seconds", "" if status.active_db_heartbeat_age_seconds is None else str(int(status.active_db_heartbeat_age_seconds)))
    db.set_background_monitor_state("user_notifier_stdout_tail_latest_timestamp", status.stdout_tail_latest_timestamp)
    db.set_background_monitor_state("user_notifier_stderr_tail_latest_timestamp", status.stderr_tail_latest_timestamp)
    db.set_background_monitor_state("user_notifier_historical_stdout_heartbeat_detected", "1" if status.historical_stdout_heartbeat_detected else "0")
    db.set_background_monitor_state("user_notifier_stale_log_evidence", "1" if status.stale_log_evidence else "0")
    if status.install_status == "loaded":
        db.set_background_monitor_state("user_notifier_last_install_at", utc_now_iso())
        db.set_background_monitor_state("notification_status", "User Alert Agent installed and running.")
    elif status.install_status in {"missing", "broken", "unloaded"}:
        db.set_background_monitor_state("notification_status", f"User Alert Agent repair required: {status.last_error}")


def _installer_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs[key] for key in ["db_path", "home", "runner", "python_executable"] if key in kwargs}


def _action_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs[key] for key in ["run_at_load", "keep_alive", "start"] if key in kwargs}


def _probe_notifier_source_database(path: Path) -> tuple[bool, str, str]:
    """Verify the notifier can read its event source without modifying it."""
    if not path.is_file():
        return False, "missing", f"Notifier event database is missing: {path}"
    try:
        uri = f"file:{path.resolve(strict=False).as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=0.25) as connection:
            check = connection.execute("PRAGMA quick_check(1)").fetchone()
            if not check or str(check[0]).lower() != "ok":
                return False, "malformed", "Notifier event database integrity check failed. Preserve the database before repair."
            connection.execute("SELECT event_id FROM background_monitor_events LIMIT 1").fetchone()
        return True, "ok", ""
    except (OSError, sqlite3.DatabaseError) as exc:
        text = str(exc).lower()
        if "no such table" in text:
            category = "schema_missing"
        else:
            category = "malformed" if any(marker in text for marker in ("malformed", "not a database", "file is encrypted")) else "unreadable"
        return False, category, f"Notifier cannot read its event database ({category}): {type(exc).__name__}."
