from __future__ import annotations

import os
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import (
    LAUNCHCTL_BIN,
    MAC_AUDIT_AGENT_ENV_DB_PATH,
    PLUTIL_BIN,
    default_monitor_db_path,
    project_root,
    user_launchctl_uid,
)
from mac_audit_agent.models import utc_now_iso


USER_NOTIFIER_LABEL = "com.mac-audit-agent.user-notifier"
USER_NOTIFIER_STDOUT = "user_notifier.stdout.log"
USER_NOTIFIER_STDERR = "user_notifier.stderr.log"
PID_RE = re.compile(r"\bpid = (\d+)\b")


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
    stdout_path: str = ""
    stderr_path: str = ""
    last_error: str = ""
    last_bootstrap_result: str = ""
    last_bootout_result: str = ""

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
    ) -> None:
        self.uid = user_launchctl_uid()
        self.user = pwd.getpwuid(self.uid)
        self.home = Path(home or self.user.pw_dir).expanduser()
        self.runner = runner or subprocess.run
        self.python_executable = python_executable or _python_executable()
        self.db_path = Path(db_path or default_monitor_db_path("user")).expanduser()
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
        return f"gui/{self.uid}"

    def ensure_directories(self) -> None:
        for directory in [self.launch_agents_dir, self.log_dir, self.app_support_dir, self.runtime_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o755)
            except OSError:
                pass

    def install_user_notifier(self, *, run_at_load: bool = True, keep_alive: bool = True, start: bool = True) -> UserNotifierStatus:
        self.ensure_directories()
        self._install_runtime_files()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.build_plist(run_at_load=run_at_load, keep_alive=keep_alive)
        self.plist_path.write_bytes(plistlib.dumps(payload))
        os.chmod(self.plist_path, 0o644)
        try:
            os.chown(self.plist_path, self.uid, self.user.pw_gid)
        except OSError:
            pass
        self._run([PLUTIL_BIN, "-lint", str(self.plist_path)])
        status = self.get_user_notifier_status()
        if status.install_status == "broken":
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
        return status

    def load_user_notifier(self) -> UserNotifierStatus:
        self.verify_user_notifier(raise_on_error=True)
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
            return status
        self._run([LAUNCHCTL_BIN, "kickstart", "-k", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"], check=False)
        return self.get_user_notifier_status()

    def unload_user_notifier(self) -> UserNotifierStatus:
        result = self._run([LAUNCHCTL_BIN, "bootout", self.launchctl_domain, str(self.plist_path)], check=False)
        status = self.get_user_notifier_status()
        status.last_bootout_result = _result_text(result)
        return status

    def restart_user_notifier(self) -> UserNotifierStatus:
        self.unload_user_notifier()
        return self.load_user_notifier()

    def repair_user_notifier(self) -> UserNotifierStatus:
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
            if payload.get("Label") != USER_NOTIFIER_LABEL:
                raise ValueError(f"plist Label must be {USER_NOTIFIER_LABEL}, got {payload.get('Label')}")
            if not status.program_arguments:
                raise ValueError("plist ProgramArguments is empty")
            mode = stat.S_IMODE(self.plist_path.stat().st_mode)
            if mode != 0o644:
                raise ValueError(f"plist mode is {oct(mode)}, expected 0o644")
            if self.plist_path.stat().st_uid != self.uid:
                raise ValueError(f"plist owner uid is {self.plist_path.stat().st_uid}, expected {self.uid}")
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
        status.loaded = result.returncode == 0
        output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        status.running = status.loaded and ("state = running" in output or "state = waiting" in output)
        pid_match = PID_RE.search(result.stdout or "")
        if pid_match:
            status.process_pid = int(pid_match.group(1))
        if status.loaded:
            status.install_status = "loaded"
        else:
            status.install_status = "unloaded"
            status.last_error = _failure(
                "launchctl print did not find the user alert agent",
                [LAUNCHCTL_BIN, "print", f"{self.launchctl_domain}/{USER_NOTIFIER_LABEL}"],
                _result_text(result),
                "Run Start or Repair User Alert Agent. The service must be loaded in gui/<uid>, not as a system LaunchDaemon.",
            )
        return status

    def build_plist(self, *, run_at_load: bool = True, keep_alive: bool = True) -> dict[str, Any]:
        pythonpath = str(self.runtime_dir)
        return {
            "Label": USER_NOTIFIER_LABEL,
            "ProgramArguments": [self.python_executable, "-m", "mac_audit_agent.user_notifier", "--run"],
            "RunAtLoad": bool(run_at_load),
            "KeepAlive": bool(keep_alive),
            "WorkingDirectory": str(self.runtime_dir),
            "EnvironmentVariables": {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
                "PYTHONPATH": pythonpath,
                MAC_AUDIT_AGENT_ENV_DB_PATH: str(self.db_path),
                "MAC_AUDIT_AGENT_MONITOR_ROLE": "user-notifier",
            },
            "StandardOutPath": str(self.stdout_path),
            "StandardErrorPath": str(self.stderr_path),
            "ProcessType": "Interactive",
        }

    def _install_runtime_files(self) -> None:
        source_root = project_root() / "mac_audit_agent"
        if not source_root.exists():
            return
        shutil.copytree(
            source_root,
            self.runtime_package_dir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
            copy_function=shutil.copyfile,
        )

    def _run(self, command: list[str], *, check: bool = True):
        result = self.runner(command, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(_failure("command failed", command, _result_text(result), "Run Repair User Alert Agent or inspect User Alert Agent Diagnostics."))
        return result


def _python_executable() -> str:
    if getattr(sys, "frozen", False):
        return sys.executable
    for candidate in ["/usr/bin/python3", sys.executable]:
        if candidate and Path(candidate).exists():
            return candidate
    return "python3"


def _result_text(result) -> str:
    return (result.stderr or result.stdout or f"exit code {result.returncode}").strip()


def _format_command(command: list[str]) -> str:
    return " ".join(command)


def _failure(cause: str, command: list[str], detail: str, fix: str) -> str:
    return f"{cause}\ncommand: {_format_command(command)}\ndetail: {detail or 'none'}\nrecommended fix: {fix}"


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
    if status.install_status == "loaded":
        db.set_background_monitor_state("user_notifier_last_install_at", utc_now_iso())
        db.set_background_monitor_state("notification_status", "User Alert Agent installed and running.")
    elif status.install_status in {"missing", "broken", "unloaded"}:
        db.set_background_monitor_state("notification_status", f"User Alert Agent repair required: {status.last_error}")


def _installer_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs[key] for key in ["db_path", "home", "runner", "python_executable"] if key in kwargs}


def _action_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs[key] for key in ["run_at_load", "keep_alive", "start"] if key in kwargs}
