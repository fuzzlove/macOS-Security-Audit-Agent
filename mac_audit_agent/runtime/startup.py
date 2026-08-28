"""Small, dependency-free application bootstrap and failure reporter.

Keep this module parseable by Python 3.8+ so an accidentally selected older
interpreter can display a useful message before importing the application.
"""

import json
import importlib.metadata
import importlib.util
import os
import platform
import shlex
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

MIN_PYTHON = (3, 9)
MAX_PYTHON = (3, 14)
APP_NAME = "macOS Security Audit Agent (MSAA)"
IMPORT_DISTRIBUTIONS = {"docx": "python-docx", "PySide6": "PySide6", "openpyxl": "openpyxl"}
STDLIB_SYMBOL_FEATURES = {
    ("enum", "StrEnum"): ("Python 3.11+", "mac_audit_agent.compat.enum.StrEnum"),
}


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def mode_name():
    if is_frozen():
        return "frozen executable"
    package_root = Path(__file__).resolve().parents[2]
    return "source checkout" if (package_root / "pyproject.toml").exists() else "installed package"


def quote_command(parts):
    if os.name == "nt":
        return subprocess_list2cmdline(parts)
    return " ".join(shlex.quote(str(part)) for part in parts)


def subprocess_list2cmdline(parts):
    # Import lazily to keep startup imports minimal.
    import subprocess

    return subprocess.list2cmdline([str(part) for part in parts])


def diagnostic_log_path():
    candidates = []
    if sys.platform == "darwin":
        candidates.append(Path.home() / "Library" / "Logs" / "MacAuditAgent")
    elif os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(Path(local) / "MacAuditAgent" / "Logs")
    else:
        candidates.append(Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "mac-audit-agent")
    candidates.extend([Path.home() / ".mac_audit_agent" / "logs", Path(tempfile.gettempdir()) / "mac-audit-agent"])
    for directory in candidates:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".write-test"
            probe.touch(exist_ok=True)
            probe.unlink()
            return directory / "startup-errors.log"
        except OSError:
            continue
    return Path(tempfile.gettempdir()) / "msaa-startup-errors.log"


def environment_lines():
    return [
        "- Python: %s" % platform.python_version(),
        "- Python executable: %s" % os.path.abspath(sys.executable),
        "- Operating system: %s" % platform.platform(),
        "- Architecture: %s" % (platform.machine() or "unknown"),
        "- Application mode: %s" % mode_name(),
    ]


def failure_message(code, problem, technical, component=None, fix_steps=None, retry=None, log_path=None):
    component = component or {}
    fix_steps = fix_steps or []
    log_path = log_path or diagnostic_log_path()
    lines = [APP_NAME + " could not start.", "", "Problem:", problem, "", "Detected environment:"]
    lines.extend(environment_lines())
    if component:
        lines.extend(["", "Component:"])
        labels = {
            "module": "Import/module name",
            "distribution": "Package/distribution name",
            "installed": "Installed version",
            "required": "Required version",
        }
        for key in ("module", "distribution", "installed", "required"):
            if key in component:
                lines.append("- %s: %s" % (labels[key], component[key]))
    lines.extend(["", "How to fix it:"])
    for index, step in enumerate(fix_steps, 1):
        lines.append("%d. %s" % (index, step))
    if retry:
        lines.append("%d. Retry: %s" % (len(fix_steps) + 1, retry))
    doctor = quote_command([sys.executable, "--doctor"] if is_frozen() else [sys.executable, "-m", "mac_audit_agent", "--doctor"])
    lines.extend(
        [
            "",
            "Additional help:",
            "- Run: %s" % doctor,
            "- Diagnostic log: %s" % log_path,
            "- Error code: %s" % code,
            "",
            "Technical details:",
            technical,
        ]
    )
    return "\n".join(lines)


def write_failure_log(code, message, exception=None):
    path = diagnostic_log_path()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_code": code,
        "message": message,
        "python": platform.python_version(),
        "executable": os.path.abspath(sys.executable),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "mode": mode_name(),
    }
    if exception is not None:
        record["exception_type"] = type(exception).__name__
        record["traceback"] = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        try:
            sys.stderr.write("MSAA could not write diagnostic log %s: %s\n" % (path, exc))
        except OSError:
            return path
    return path


def python_supported():
    return MIN_PYTHON <= sys.version_info[:2] <= MAX_PYTHON


def is_root_user():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def requested_mode(argv):
    args = set(argv)
    if "--doctor" in args:
        return "doctor"
    if args.intersection({"--system-monitor-service", "--user-monitor-service", "--user-notifier-service", "--service-watchdog", "--sensor-health"}):
        return "service"
    if argv and (argv[0] == "protection" or "protection" in args):
        return "protection"
    if argv and (argv[0] == "integrity" or "integrity" in args):
        return "integrity"
    return "gui" if not argv or "--packaged-gui-smoke" in args else "cli"


def root_gui_message():
    gui_command = quote_command([sys.executable, "-m", "mac_audit_agent"])
    protection_command = quote_command(
        [
            "sudo", sys.executable, "-m", "mac_audit_agent.protection", "install",
            "--mode", "protected", "--with-system-daemon", "--with-user-notifier",
            "--apply-current-settings", "--verify", "--verbose",
        ]
    )
    return "\n".join(
        [
            "Do not start the MSAA GUI with sudo.",
            "Start the GUI as your normal user. MSAA uses elevation only for specific protection install or repair steps.",
            "",
            "GUI:",
            "  %s" % gui_command,
            "",
            "Protection install (headless):",
            "  %s" % protection_command,
        ]
    )


def unsupported_python_message():
    detected = "%d.%d.%d" % sys.version_info[:3]
    executable = os.path.abspath(sys.executable)
    if os.name == "nt":
        setup = "Install standard CPython 3.14, then run: py -3.14 -m venv .venv"
        activate = r".venv\Scripts\Activate.ps1"
        retry = "py -3.14 -m mac_audit_agent --doctor"
    else:
        setup = "Use this standard CPython 3.14 interpreter to create an environment: %s" % quote_command([sys.executable, "-m", "venv", ".venv"])
        activate = "source .venv/bin/activate"
        retry = quote_command([sys.executable, "-m", "mac_audit_agent", "--doctor"])
    return failure_message(
        "PY001",
        "Python %s is unsupported. MSAA supports standard CPython 3.10 through 3.14." % detected,
        "The invoked interpreter is outside the supported range: %s" % executable,
        fix_steps=[setup, "Activate the environment: %s" % activate, "Install with: python -m pip install \"%s\"" % _install_target("gui")],
        retry=retry,
    )


def classify_import_failure(exc):
    missing = getattr(exc, "name", None) or "unknown"
    message = str(exc)
    for (module, symbol), (required_version, project_resolution) in STDLIB_SYMBOL_FEATURES.items():
        if missing == module and "cannot import name %r" % symbol in message:
            return (
                "PYCOMPAT001",
                "The runtime is missing a standard-library feature used by MSAA.",
                {
                    "module": "%s.%s" % (module, symbol),
                    "distribution": "Python standard library (not a pip package)",
                    "installed": "unavailable in Python %s" % platform.python_version(),
                    "required": required_version + " natively; MSAA provides a compatibility shim",
                },
                [
                    "No pip package is required. Do not install enum or enum34.",
                    "MSAA should resolve this internally through %s." % project_resolution,
                    "Run the doctor command below and report the compatibility trace if this reaches startup.",
                ],
            )
    distribution = IMPORT_DISTRIBUTIONS.get(missing.split(".", 1)[0], missing.split(".", 1)[0])
    native_markers = ("dlopen", "DLL load failed", "shared object", "image not found", "wrong architecture")
    native = any(marker.lower() in str(exc).lower() for marker in native_markers)
    if is_frozen():
        return (
            "PKG001",
            "This application bundle is incomplete or incompatible with this computer.",
            {},
            ["Reinstall MSAA using a build for %s/%s." % (platform.system(), platform.machine()), "If the problem continues, replace the download and check antivirus or quarantine history."],
        )
    if native:
        return (
            "SYS001",
            "A required native library could not be loaded.",
            {"module": missing, "distribution": distribution, "installed": "installed but not loadable", "required": "compatible OS/architecture build"},
            ["Recreate the virtual environment with this interpreter.", "Reinstall the affected package: %s" % quote_command([sys.executable, "-m", "pip", "install", "--force-reinstall", distribution])],
        )
    root_module = missing.split(".", 1)[0]
    if isinstance(exc, ModuleNotFoundError) and root_module in getattr(sys, "stdlib_module_names", set()):
        return (
            "PYCOMPAT002",
            "A Python standard-library module is unavailable in this runtime.",
            {"module": missing, "distribution": "Python standard library", "installed": "unavailable", "required": "a complete supported CPython installation"},
            ["No pip package is required.", "Reinstall or select a complete supported CPython runtime, then run the doctor command below."],
        )
    if not isinstance(exc, ModuleNotFoundError):
        return (
            "APPIMPORT001",
            "An installed MSAA component failed while being imported.",
            {"module": missing, "distribution": distribution, "installed": "present but import failed", "required": "compatible MSAA source and runtime"},
            ["Do not install a package named after a standard-library module.", "Run the doctor command below and report the internal import trace."],
        )
    return (
        "DEP001",
        "A required Python component could not be imported.",
        {"module": missing, "distribution": distribution, "installed": "not installed" if isinstance(exc, ModuleNotFoundError) else "installed but import failed", "required": "see project installation extra"},
        ["Confirm this is the interpreter where MSAA was installed: %s" % sys.executable, "Install the requested feature: %s" % quote_command([sys.executable, "-m", "pip", "install", _install_target("gui")])],
    )


def report_exception(exc, debug=False):
    if isinstance(exc, (ImportError, ModuleNotFoundError)):
        code, problem, component, fixes = classify_import_failure(exc)
    elif isinstance(exc, MemoryError):
        code, problem, component, fixes = "MEM001", "MSAA ran out of memory and stopped safely.", {}, ["Close memory-intensive applications and retry.", "Use the one-directory build instead of the one-file build when available."]
    elif isinstance(exc, PermissionError):
        code, problem, component, fixes = "FS001", "MSAA cannot access a required file or directory.", {}, ["Choose a writable per-user location and retry.", "Do not run pip with administrator privileges; use a virtual environment."]
    else:
        code, problem, component, fixes = "APP999", "MSAA encountered an unexpected error.", {}, ["Run the diagnostic command shown below.", "Report the diagnostic log with secrets removed if the problem continues."]
    path = write_failure_log(code, str(exc), exc)
    text = failure_message(code, problem, "%s: %s" % (type(exc).__name__, exc), component, fixes, log_path=path)
    if debug:
        text += "\n\nDebug traceback:\n" + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return code, text


def gui_dependency_failure():
    if platform.system() != "Darwin":
        return failure_message(
            "SYS003",
            "The MSAA desktop application is supported only on macOS.",
            "Detected operating system: %s" % platform.system(),
            fix_steps=["Run the environment doctor or headless packaging commands on this system.", "Use a supported macOS computer for security collection and the GUI."],
        )
    try:
        installed = importlib.metadata.version("PySide6")
    except importlib.metadata.PackageNotFoundError:
        installed = "not installed"
    if importlib.util.find_spec("PySide6") is None:
        if is_frozen():
            return failure_message("PKG001", "The application bundle is missing its GUI runtime.", "PySide6 was not bundled.", fix_steps=["Reinstall MSAA from a trusted macOS release archive."])
        command = quote_command([sys.executable, "-m", "pip", "install", _install_target("gui")])
        return failure_message("DEP314001", "MSAA supports Python 3.14, but the GUI dependency PySide6 is not installed for this interpreter.", "PySide6 could not be located.", {"module": "PySide6", "distribution": "PySide6", "installed": installed, "required": ">=6.10.1,<6.12"}, ["Create or activate an environment made by this interpreter: %s" % quote_command([sys.executable, "-m", "venv", ".venv"]), "Run: %s" % command])
    observed = tuple(int(part) for part in installed.split(".")[:2] if part.isdigit())
    if observed and observed < (6, 10):
        command = quote_command([sys.executable, "-m", "pip", "install", "--upgrade", _install_target("gui")])
        return failure_message("DEP314002", "The installed PySide6 version is too old for Python 3.14 MSAA.", "PySide6 %s does not satisfy >=6.10.1,<6.12." % installed, {"module": "PySide6", "distribution": "PySide6", "installed": installed, "required": ">=6.10.1,<6.12"}, ["Upgrade the GUI extra with: %s" % command])
    return None


def _install_target(extra):
    return ".[{}]".format(extra) if mode_name() == "source checkout" else "macos-security-audit-agent[{}]".format(extra)


def display_frozen_failure(message):
    if not is_frozen():
        return False
    argv = set(sys.argv[1:])
    prohibited = bool(
        argv.intersection({"--json", "--doctor", "--smoke-test", "--no-dialogs", "--user-notifier-service", "--system-monitor-service", "--user-monitor-service", "--service-watchdog", "--sensor-health"})
        or os.environ.get("MSAA_NO_DIALOGS") == "1"
        or os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("MSAA_UAT_AUTOMATION") == "1"
    )
    if prohibited:
        write_failure_log("GUI314001", "Blocking startup dialog suppressed in automation/service mode.")
        return False
    errors = []
    try:
        from mac_audit_agent.runtime.qapplication_guard import assert_qapplication_allowed
        assert_qapplication_allowed()
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance() or QApplication([])
        QMessageBox.critical(None, APP_NAME, message)
        app.processEvents()
        return True
    except Exception as exc:
        errors.append(exc)
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror(APP_NAME, message)
        root.destroy()
        return True
    except Exception as exc:
        errors.append(exc)
        write_failure_log("APP999", "Unable to display frozen startup dialog: %s" % "; ".join(str(item) for item in errors), exc)
        return False


def error_code_from_message(message, default="APP999"):
    marker = "- Error code: "
    for line in str(message).splitlines():
        if line.startswith(marker):
            value = line[len(marker) :].strip()
            return value or default
    return default


__all__ = [
    "MAX_PYTHON",
    "MIN_PYTHON",
    "diagnostic_log_path",
    "failure_message",
    "gui_dependency_failure",
    "is_root_user",
    "is_frozen",
    "python_supported",
    "requested_mode",
    "report_exception",
    "root_gui_message",
    "display_frozen_failure",
    "error_code_from_message",
    "unsupported_python_message",
    "write_failure_log",
]
