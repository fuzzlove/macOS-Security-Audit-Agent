from __future__ import annotations

import os
import plistlib
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorStatus


LAUNCH_AGENT_LABEL = "com.mac-audit-agent.monitor"
LAUNCHCTL_BIN = "/bin/launchctl"
PLUTIL_BIN = "/usr/bin/plutil"
LOG_BIN = "/usr/bin/log"


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def monitor_script_path() -> Path:
    return project_root() / "mac_audit_agent" / "monitor.py"


def runtime_root() -> Path:
    return Path.home() / ".mac_audit_agent" / "runtime"


def runtime_package_root() -> Path:
    return runtime_root() / "mac_audit_agent"


def runtime_monitor_script_path() -> Path:
    return runtime_package_root() / "monitor.py"


@dataclass
class LaunchAgentPaths:
    plist_path: Path
    stdout_path: Path
    stderr_path: Path


def default_launch_agent_paths() -> LaunchAgentPaths:
    logs_dir = Path.home() / ".mac_audit_agent" / "logs"
    launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
    return LaunchAgentPaths(
        plist_path=launch_agents_dir / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=logs_dir / "background_monitor.stdout.log",
        stderr_path=logs_dir / "background_monitor.stderr.log",
    )


def launchctl_target() -> str:
    return f"gui/{os.getuid()}"


def build_launch_agent_plist(*, db_path: Path, poll_interval_seconds: int = 15, python_executable: str | None = None) -> dict:
    paths = default_launch_agent_paths()
    root = runtime_root()
    monitor_path = runtime_monitor_script_path()
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            python_executable or "/usr/bin/python3",
            str(monitor_path),
            "--run",
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Interactive",
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "StandardOutPath": str(paths.stdout_path),
        "StandardErrorPath": str(paths.stderr_path),
    }


def _format_command(command: list[str]) -> str:
    return " ".join(command)


PID_RE = re.compile(r"\bpid = (\d+)\b")


class LaunchAgentManager:
    def __init__(self, db_path: Path, runner=None) -> None:
        self.db_path = db_path
        self.paths = default_launch_agent_paths()
        self.runner = runner or subprocess.run

    def install(self, poll_interval_seconds: int = 15) -> Path:
        payload = build_launch_agent_plist(db_path=self.db_path, poll_interval_seconds=poll_interval_seconds)
        if payload.get("Label") != LAUNCH_AGENT_LABEL:
            raise RuntimeError(f"Invalid LaunchAgent Label: expected {LAUNCH_AGENT_LABEL}, got {payload.get('Label')}")
        self._ensure_user_paths()
        self._install_runtime_files()
        self.paths.plist_path.write_bytes(plistlib.dumps(payload))
        os.chmod(self.paths.plist_path, 0o644)
        current_user = pwd.getpwuid(os.getuid())
        staff_gid = grp.getgrnam("staff").gr_gid
        os.chown(self.paths.plist_path, current_user.pw_uid, staff_gid)
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        return self.paths.plist_path

    def uninstall(self) -> None:
        if self.paths.plist_path.exists():
            self.paths.plist_path.unlink()

    def repair(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        for candidate in [
            self.paths.plist_path,
            Path("/Library/LaunchAgents") / f"{LAUNCH_AGENT_LABEL}.plist",
            Path("/Library/LaunchDaemons") / f"{LAUNCH_AGENT_LABEL}.plist",
        ]:
            try:
                if candidate.exists():
                    candidate.unlink()
                    notes.append(f"removed: {candidate}")
            except OSError as exc:
                notes.append(f"remove failed: {candidate} | {exc}")
        plist_path = self.install(poll_interval_seconds=poll_interval_seconds)
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def force_reinstall(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        try:
            if self.paths.plist_path.exists():
                self.paths.plist_path.unlink()
                notes.append(f"removed: {self.paths.plist_path}")
        except OSError as exc:
            notes.append(f"remove failed: {self.paths.plist_path} | {exc}")
        plist_path = self.install(poll_interval_seconds=poll_interval_seconds)
        notes.append(f"recreated: {plist_path}")
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def start(self) -> None:
        self._bootstrap_preflight()
        for command in self._bootout_commands():
            self._run(
                command,
                tolerate=self._bootout_tolerate(),
            )
        try:
            self._run([LAUNCHCTL_BIN, "bootstrap", launchctl_target(), str(self.paths.plist_path)], tolerate={"already bootstrapped"})
        except Exception as exc:
            launchd_tail = self._launchd_log_tail()
            message = str(exc)
            if launchd_tail:
                message = f"{message}\nlaunchd log tail:\n{launchd_tail}"
            raise RuntimeError(message) from exc
        self._run([LAUNCHCTL_BIN, "kickstart", "-k", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"])

    def stop(self) -> None:
        self._run([LAUNCHCTL_BIN, "bootout", launchctl_target(), str(self.paths.plist_path)], tolerate={"could not find specified service"})

    def status(self) -> BackgroundMonitorStatus:
        installed = self.paths.plist_path.exists()
        loaded = False
        running = False
        last_error = ""
        process_pid = None
        if installed:
            command = [LAUNCHCTL_BIN, "print", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"]
            result = self._run(command, check=False)
            stdout = (result.stdout or "").lower()
            loaded = result.returncode == 0
            running = result.returncode == 0 and ("state = running" in stdout or "state = waiting" in stdout)
            pid_match = PID_RE.search(result.stdout or "")
            if pid_match:
                process_pid = int(pid_match.group(1))
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "command failed").strip()
                last_error = f"Command failed: {_format_command(command)}\nstderr:\n{detail}"
        return BackgroundMonitorStatus(
            installed=installed,
            loaded=loaded,
            running=running,
            enabled=installed,
            plist_path=str(self.paths.plist_path),
            label=LAUNCH_AGENT_LABEL,
            log_path=str(self.paths.stdout_path),
            db_path=str(self.db_path),
            process_pid=process_pid,
            last_error=last_error,
            current_launchctl_domain=launchctl_target(),
        )

    def show_logs(self) -> str:
        return str(self.paths.stdout_path)

    def _bootstrap_preflight(self) -> None:
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        payload = plistlib.loads(self.paths.plist_path.read_bytes())
        program_arguments = list(payload.get("ProgramArguments", []))
        expected_program_arguments = ["/usr/bin/python3", str(runtime_monitor_script_path()), "--run"]
        if program_arguments != expected_program_arguments:
            raise RuntimeError(
                "LaunchAgent preflight failed: ProgramArguments must be "
                f"{expected_program_arguments}, got {program_arguments}"
            )
        working_directory = Path(str(payload.get("WorkingDirectory", ""))).expanduser()
        if "Documents" in str(working_directory) or "Desktop" in str(working_directory) or "Downloads" in str(working_directory):
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory must not be inside a protected folder: {working_directory}")
        if not working_directory.exists():
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory does not exist: {working_directory}")
        if working_directory != runtime_root():
            raise RuntimeError(
                f"LaunchAgent preflight failed: WorkingDirectory must be {runtime_root()}, got {working_directory}"
            )
        for log_parent in [self.paths.stdout_path.parent, self.paths.stderr_path.parent]:
            if not log_parent.exists():
                raise RuntimeError(f"LaunchAgent preflight failed: log directory does not exist: {log_parent}")
        current_uid = os.getuid()
        plist_stat = self.paths.plist_path.stat()
        mode = stat.S_IMODE(plist_stat.st_mode)
        if plist_stat.st_uid != current_uid:
            owner_name = pwd.getpwuid(plist_stat.st_uid).pw_name
            current_name = pwd.getpwuid(current_uid).pw_name
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist owner is {owner_name}, expected {current_name}. "
                f"Repair: sudo chown {current_name}:staff {self.paths.plist_path}"
            )
        if mode != 0o644:
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist mode is {oct(mode)}, expected 0o644. "
                f"Repair: chmod 644 {self.paths.plist_path}"
            )

    def _ensure_user_paths(self) -> None:
        current_uid = os.getuid()
        current_user = pwd.getpwuid(current_uid)
        staff_gid = grp.getgrnam("staff").gr_gid
        for directory in [self.paths.stdout_path.parent, self.paths.plist_path.parent, runtime_root(), runtime_package_root()]:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o755)
            except OSError:
                pass
            try:
                os.chown(directory, current_uid, staff_gid)
            except OSError:
                pass
            if not os.access(directory, os.W_OK):
                raise RuntimeError(
                    f"LaunchAgent path is not writable: {directory}. "
                    f"Repair: sudo chown -R {current_user.pw_name}:staff {directory}"
                )

    def _install_runtime_files(self) -> None:
        source_root = project_root() / "mac_audit_agent"
        target_root = runtime_package_root()
        current_uid = os.getuid()
        staff_gid = grp.getgrnam("staff").gr_gid
        shutil.copytree(
            source_root,
            target_root,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
            copy_function=shutil.copyfile,
        )
        for path in sorted(target_root.rglob("*")):
            try:
                if path.is_dir():
                    path.chmod(0o755)
                else:
                    path.chmod(0o755 if path.name == "monitor.py" else 0o644)
            except OSError:
                pass
            try:
                os.chown(path, current_uid, staff_gid)
            except OSError:
                pass
        try:
            os.chown(target_root, current_uid, staff_gid)
            os.chown(runtime_root(), current_uid, staff_gid)
        except OSError:
            pass

    def _bootout_commands(self) -> list[list[str]]:
        return [
            [LAUNCHCTL_BIN, "bootout", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"],
            [LAUNCHCTL_BIN, "bootout", launchctl_target(), str(self.paths.plist_path)],
        ]

    def _bootout_tolerate(self) -> set[str]:
        return {
            "could not find specified service",
            "service cannot load in requested session",
            "no such process",
            "not loaded",
            "domain does not support the specified action",
            "input/output error",
        }

    def _launchd_log_tail(self) -> str:
        if not Path(LOG_BIN).exists():
            return ""
        result = self._run(
            [
                LOG_BIN,
                "show",
                "--style",
                "compact",
                "--last",
                "5m",
                "--predicate",
                'process == "launchd"',
            ],
            check=False,
        )
        content = (result.stdout or result.stderr or "").strip()
        if not content:
            return ""
        lines = content.splitlines()
        return "\n".join(lines[-30:])

    def _run(self, command: list[str], *, check: bool = True, tolerate: set[str] | None = None):
        result = self.runner(command, capture_output=True, text=True)
        tolerate = tolerate or set()
        stderr = (result.stderr or "").lower()
        stdout = (result.stdout or "").lower()
        if check and result.returncode != 0 and not any(item in stderr or item in stdout for item in tolerate):
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise RuntimeError(f"Command failed: {_format_command(command)}\nstderr:\n{detail}")
        return result
