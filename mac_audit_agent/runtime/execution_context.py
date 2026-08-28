from __future__ import annotations

import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExecutionContext:
    process_name: str
    parent_process: str
    responsible_process: str
    python_executable: str
    python_version: str
    architecture: str
    running_from_terminal: bool
    running_from_codex: bool
    running_from_launchagent: bool
    running_from_launchdaemon: bool
    running_from_main_gui: bool
    running_from_user_notifier: bool
    running_pre_uat: bool
    running_integrity_cli: bool
    running_release_verify: bool
    running_headless_cli: bool
    can_import_gui: bool
    can_create_qapplication: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def detect_execution_context() -> ExecutionContext:
    argv = " ".join(sys.argv)
    process_name = Path(sys.argv[0] or sys.executable).name
    parent_process = _process_name(os.getppid())
    responsible_process = os.environ.get("MSAA_RESPONSIBLE_PROCESS", parent_process)
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    running_from_codex = _contains_any(" ".join([argv, parent_process, responsible_process, os.environ.get("TERM_PROGRAM", "")]), {"codex"})
    running_from_terminal = bool(os.environ.get("TERM_PROGRAM") or os.environ.get("TERM") or parent_process in {"zsh", "bash", "fish", "Terminal", "iTerm2"})
    running_integrity_cli = "mac_audit_agent.integrity" in argv
    running_pre_uat = "mac_audit_agent.quality.pre_uat_audit" in argv
    running_release_verify = "release_verify" in argv or "release_integrity" in argv
    running_from_user_notifier = "user_notifier" in argv or os.environ.get("MSAA_USER_NOTIFIER_RUNTIME") == "1"
    running_from_main_gui = "gui_app" in argv or os.environ.get("MSAA_MAIN_GUI_RUNTIME") == "1"
    running_from_launchagent = "LaunchAgent" in parent_process or os.environ.get("LaunchAgent") == "1" or os.environ.get("MSAA_LAUNCHAGENT") == "1"
    running_from_launchdaemon = "launchd" in parent_process.lower() and not running_from_launchagent or os.environ.get("MSAA_LAUNCHDAEMON") == "1"
    running_headless_cli = running_integrity_cli or running_pre_uat or running_release_verify or (running_from_terminal and not running_from_main_gui and not running_from_user_notifier)

    gil_enabled = getattr(sys, "_is_gil_enabled", lambda: True)()
    gui_runtime_supported = (3, 10) <= sys.version_info[:2] <= (3, 14) and sys.implementation.name == "cpython" and gil_enabled
    can_gui_process = running_from_main_gui or (running_from_user_notifier and running_from_launchagent)
    can_import_gui = can_gui_process and gui_runtime_supported and not running_from_codex
    can_create_qapplication = can_import_gui
    reason = "GUI import allowed for explicit MSAA GUI runtime." if can_import_gui else "Headless/CLI context or unsupported Python GUI runtime blocks Qt/AppKit initialization."
    if sys.version_info[:2] == (3, 14) and not gil_enabled and can_gui_process:
        reason = "The free-threaded Python 3.14 ABI is tracked separately and is not qualified for MSAA GUI rendering."
    return ExecutionContext(
        process_name=process_name,
        parent_process=parent_process,
        responsible_process=responsible_process,
        python_executable=sys.executable,
        python_version=python_version,
        architecture=platform.machine(),
        running_from_terminal=running_from_terminal,
        running_from_codex=running_from_codex,
        running_from_launchagent=running_from_launchagent,
        running_from_launchdaemon=running_from_launchdaemon,
        running_from_main_gui=running_from_main_gui,
        running_from_user_notifier=running_from_user_notifier,
        running_pre_uat=running_pre_uat,
        running_integrity_cli=running_integrity_cli,
        running_release_verify=running_release_verify,
        running_headless_cli=running_headless_cli,
        can_import_gui=can_import_gui,
        can_create_qapplication=can_create_qapplication,
        reason=reason,
    )


def _process_name(pid: int) -> str:
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], text=True, capture_output=True, check=False, timeout=2)
        return Path(result.stdout.strip()).name
    except Exception:
        return ""


def _contains_any(value: str, needles: set[str]) -> bool:
    lower = value.lower()
    return any(needle in lower for needle in needles)


__all__ = ["ExecutionContext", "detect_execution_context"]
