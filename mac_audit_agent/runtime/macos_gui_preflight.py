"""macOS GUI safety preflight that never imports Qt or AppKit in-process."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import platform
import signal
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.runtime.gui_launch_modes import GuiLaunchMode, matching_crash_marker, record_gui_crash


@dataclass(frozen=True)
class MacOSGuiPreflightResult:
    allowed: bool
    failure_code: str
    reason: str
    python_executable: str
    python_version: str
    macos_version: str
    architecture: str
    parent_process: str
    responsible_process: str
    is_terminal_launch: bool
    is_app_bundle_launch: bool
    is_source_checkout: bool
    is_root: bool
    display_session_available: bool
    launchservices_safe: bool
    qt_available: bool
    pyside_available: bool
    qt_version: str
    pyside_version: str
    launch_mode: str
    recommended_action: str
    recommended_commands: tuple[str, ...]
    probe: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _process_name(pid: int) -> str:
    try:
        result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, timeout=2, check=False)
        return (result.stdout or "").strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _display_session_available() -> bool:
    if sys.platform != "darwin" or os.environ.get("SSH_CONNECTION"):
        return False
    try:
        result = subprocess.run(["/bin/launchctl", "print", "gui/%d" % os.getuid()], capture_output=True, timeout=3, check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def _python_version_tuple() -> tuple[int, int, int]:
    return tuple(sys.version_info[:3])


def run_qt_import_probe(timeout: float = 8.0) -> dict[str, Any]:
    command = [sys.executable, "-m", "mac_audit_agent.runtime.qt_smoke_probe", "--json"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return {"safe": False, "timed_out": True, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "exit_code": None, "signal": None}
    except OSError as exc:
        return {"safe": False, "error": "%s: %s" % (type(exc).__name__, exc), "exit_code": None, "signal": None}
    parsed: dict[str, Any] = {}
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, TypeError):
            parsed = {}
    terminated_signal = -result.returncode if result.returncode < 0 else None
    parsed.update({"safe": bool(parsed.get("safe")) and result.returncode == 0, "exit_code": result.returncode, "signal": terminated_signal, "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]})
    if terminated_signal == signal.SIGABRT:
        parsed["crash_indication"] = "SIGABRT during Qt import probe"
    return parsed


def run_qapplication_probe(timeout: float = 12.0) -> dict[str, Any]:
    command = [sys.executable, "-m", "mac_audit_agent.runtime.qt_smoke_probe", "--json", "--allow-qapplication-probe"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return {"safe": False, "timed_out": True, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "exit_code": None, "signal": None}
    except OSError as exc:
        return {
            "safe": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "signal": None,
        }
    terminated_signal = -result.returncode if result.returncode < 0 else None
    payload: dict[str, Any] = {}
    try:
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        payload = {}
    payload.update(
        {
            "safe": bool(payload.get("safe")) and result.returncode == 0,
            "exit_code": result.returncode,
            "signal": terminated_signal,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
        }
    )
    if terminated_signal == signal.SIGABRT:
        payload["crash_indication"] = "SIGABRT during isolated QApplication probe"
    if terminated_signal:
        signature = "signal %s during isolated QApplication probe: %s" % (terminated_signal, result.stderr[-500:])
        try:
            record_gui_crash(qt_version=str(payload.get("qt_version", "unknown")), pyside_version=str(payload.get("pyside_version", _package_version("PySide6"))), launch_mode=GuiLaunchMode.TERMINAL_DIRECT.value, crash_signature=signature)
        except OSError:
            payload["marker_write_failed"] = True
    return payload


def run_macos_gui_preflight(*, run_probe: bool = True, allow_qapplication_probe: bool = False) -> MacOSGuiPreflightResult:
    version_tuple = _python_version_tuple()
    python_version = ".".join(str(item) for item in version_tuple)
    executable = os.path.realpath(sys.executable)
    parent = _process_name(os.getppid())
    responsible = os.environ.get("TERM_PROGRAM", "") or parent
    terminal = bool(os.environ.get("TERM_PROGRAM")) or Path(parent).name in {"zsh", "bash", "fish", "Terminal", "iTerm2"}
    app_bundle = bool(getattr(sys, "frozen", False)) or ".app/Contents/MacOS/" in executable
    project_root = Path(__file__).resolve().parents[2]
    source_checkout = (project_root / "pyproject.toml").is_file() and not app_bundle
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    gui_python_validated = (3, 10) <= version_tuple[:2] <= (3, 13)
    display = _display_session_available()
    pyside_available = importlib.util.find_spec("PySide6") is not None
    pyside_version = _package_version("PySide6")
    if root:
        probe = {"safe": False, "skipped": True, "reason": "Root GUI was blocked before any Qt probe."}
    elif not gui_python_validated:
        probe = {"safe": False, "skipped": True, "reason": "Unvalidated GUI Python was blocked before any Qt probe."}
    else:
        probe = run_qt_import_probe() if run_probe and pyside_available else {"safe": pyside_available, "skipped": not run_probe}
    known_unsafe_python310_terminal = terminal and source_checkout and version_tuple[:2] == (3, 10)
    if allow_qapplication_probe and probe.get("safe") and not known_unsafe_python310_terminal:
        probe["qapplication"] = run_qapplication_probe()
    elif allow_qapplication_probe and known_unsafe_python310_terminal:
        probe["qapplication"] = {"safe": False, "skipped": True, "reason": "Known-unsafe Python 3.10 Terminal source-checkout context; probe blocked before QApplication."}
    qt_version = str(probe.get("qt_version", "unknown"))
    qt_available = bool(probe.get("safe"))
    launch_mode = GuiLaunchMode.APP_BUNDLE.value if app_bundle else GuiLaunchMode.TERMINAL_DIRECT.value if terminal else GuiLaunchMode.BLOCKED.value
    prior_crash = matching_crash_marker(python_executable=executable, python_version=python_version, launch_mode=launch_mode)
    commands = (
        "%s -m mac_audit_agent --doctor" % sys.executable,
        "python3.12 launcher.py --safe-gui-check",
        "python3.13 launcher.py --safe-gui-check",
        'open "dist/MSAA.app"',
        "sudo python3.12 -m mac_audit_agent.protection install --mode protected --with-system-daemon --with-user-notifier --apply-current-settings --verify --verbose",
    )
    allowed = True
    code = ""
    reason = "The macOS GUI launch context passed the non-destructive preflight."
    action = "Start the guarded GUI runtime."
    launchservices_safe = app_bundle or (display and terminal and version_tuple[:2] in {(3, 11), (3, 12), (3, 13)})
    if root:
        allowed, code, reason = False, "GUI_ROOT_NOT_ALLOWED", "Do not start the MSAA GUI with sudo."
    elif sys.platform != "darwin":
        allowed, code, reason = False, "GUI_UNKNOWN_UNSAFE_CONTEXT", "The MSAA GUI is supported only in a validated macOS GUI session."
    elif not gui_python_validated:
        allowed, code, reason = False, "GUI_PYTHON_VERSION_UNVALIDATED", "This Python version is not validated for the MSAA GUI."
    elif not pyside_available:
        allowed, code, reason = False, "GUI_PYSIDE_MISSING", "PySide6 is unavailable for the selected GUI action."
    elif not qt_available:
        qapplication = probe.get("qapplication", {})
        reason = "The isolated QApplication probe was rejected by the current macOS GUI services context." if qapplication and not qapplication.get("safe") else "The isolated PySide/Qt import probe did not complete safely."
        allowed, code = False, "GUI_QT_PLATFORM_UNSAFE"
    elif prior_crash:
        allowed, code, reason = False, "GUI_APPKIT_PREFLIGHT_FAILED", "This exact Python and launch mode previously crashed during GUI startup; direct retry is blocked."
    elif terminal and source_checkout and version_tuple[:2] == (3, 10):
        allowed, code, reason = False, "GUI_UNSAFE_TERMINAL_QT_COCOA", "Python 3.10 is supported generally, but this Terminal source-checkout Qt Cocoa/AppKit context is unsafe."
    elif not display:
        allowed, code, reason = False, "GUI_APPKIT_PREFLIGHT_FAILED", "No usable logged-in macOS GUI launchd session was detected."
    elif source_checkout and not launchservices_safe:
        allowed, code, reason = False, "GUI_SOURCE_CHECKOUT_REQUIRES_SAFE_LAUNCH", "This source checkout requires an app-bundle or validated direct-launch context."
    if not allowed:
        action = "Run doctor, use Python 3.12/3.13 with the safe check, or launch an app bundle."
        launch_mode = GuiLaunchMode.BLOCKED.value
    return MacOSGuiPreflightResult(allowed, code, reason, executable, python_version, platform.mac_ver()[0] or platform.release(), platform.machine(), parent, responsible, terminal, app_bundle, source_checkout, root, display, launchservices_safe, qt_available, pyside_available, qt_version, pyside_version, launch_mode, action, commands, probe)


def format_preflight_block(result: MacOSGuiPreflightResult) -> str:
    public_code = {
        "GUI_PYSIDE_MISSING": "DEP003",
        "GUI_ROOT_NOT_ALLOWED": "GUIROOT001",
        "GUI_PYTHON_VERSION_UNVALIDATED": "PY001",
    }.get(result.failure_code, "GUIQT001")
    if result.failure_code == "GUI_ROOT_NOT_ALLOWED":
        return "\n".join(
            [
                "GUIROOT001 / GUI_ROOT_NOT_ALLOWED",
                "",
                "MSAA was launched with sudo. The GUI will not start as root. Did you mean to install Active Protection?",
                "",
                "Do not start the MSAA GUI with sudo.",
                "macOS GUI apps must run in the logged-in user session. Running the MSAA GUI with sudo can break "
                "LaunchAgent routing, user notifier delivery, user settings paths, and Qt/AppKit startup.",
                "",
                "If you wanted to install protection (sudo is correct for this headless action):",
                "  sudo python3.12 launcher.py --install-protection",
                "  sudo python3.12 -m mac_audit_agent.protection install --mode protected --with-system-daemon --with-user-notifier --apply-current-settings --verify --verbose",
                "",
                "If you wanted to repair protection:",
                "  sudo python3.12 launcher.py --repair-protection",
                "  sudo python3.12 -m mac_audit_agent.protection repair --mode protected --repair-system-daemon --repair-user-notifier --repair-settings-sync --verify --verbose",
                "",
                "If you wanted the GUI, return to your normal user account and run:",
                "  python3.12 launcher.py",
                "  python3.13 launcher.py",
                '  open "dist/MSAA.app"',
                "",
                "For diagnostics (sudo is not needed):",
                "  python3.12 -m mac_audit_agent --doctor",
            ]
        )
    commands = "\n".join("%d. %s" % (index, command) for index, command in enumerate(result.recommended_commands, 1))
    return "\n".join(
        [
            "MSAA did not start the graphical interface because this Python/Qt/macOS launch context is unsafe.",
            "",
            "Detected:",
            "- Python: %s" % result.python_version,
            "- Python executable: %s" % result.python_executable,
            "- Launch mode: %s" % ("Terminal source checkout" if result.is_terminal_launch and result.is_source_checkout else result.launch_mode),
            "- Qt/PySide: %s / %s" % (result.qt_version, result.pyside_version),
            "- Parent/responsible process: %s / %s" % (result.parent_process, result.responsible_process),
            "- Risk: %s" % result.reason,
            "- Error code: %s (%s)" % (public_code, result.failure_code or "GUI_UNKNOWN_UNSAFE_CONTEXT"),
            "",
            "What still works:",
            "- doctor and integrity verification",
            "- protection doctor/install/repair",
            "- headless reports and diagnostics",
            "",
            "Recommended:",
            commands,
        ]
    )


__all__ = ["MacOSGuiPreflightResult", "format_preflight_block", "run_macos_gui_preflight", "run_qapplication_probe", "run_qt_import_probe"]
