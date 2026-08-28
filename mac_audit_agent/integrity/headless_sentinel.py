from __future__ import annotations

import sys
import json
import os
import subprocess
from pathlib import Path
from dataclasses import asdict, dataclass, field


FORBIDDEN_HEADLESS_MODULE_ROOTS = {"PySide6", "PyQt6", "PyQt5", "AppKit", "Cocoa", "objc"}
FORBIDDEN_HEADLESS_MODULES = {
    "PySide6",
    "PySide6.QtWidgets",
    "PySide6.QtGui",
    "PySide6.QtCore",
    "PyQt5",
    "PyQt6",
    "AppKit",
    "Cocoa",
    "objc",
    "mac_audit_agent.ui.main_window",
    "mac_audit_agent.ui.cve_radar_panel",
    "mac_audit_agent.ui.family_safety_panel",
    "mac_audit_agent.alerts.overlay_manager",
}
FORBIDDEN_HEADLESS_MODULE_PARTS = {"QtWidgets", "QtGui"}


@dataclass(slots=True)
class HeadlessSentinelResult:
    headless_safe: bool
    imported_gui_modules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def snapshot_headless_imports() -> HeadlessSentinelResult:
    offenders = []
    for name in sorted(sys.modules):
        root = name.split(".", 1)[0]
        parts = set(name.split("."))
        if name in FORBIDDEN_HEADLESS_MODULES or root in FORBIDDEN_HEADLESS_MODULE_ROOTS or parts & FORBIDDEN_HEADLESS_MODULE_PARTS:
            offenders.append(name)
    return HeadlessSentinelResult(not offenders, offenders)


def assert_headless_integrity_safe() -> HeadlessSentinelResult:
    result = snapshot_headless_imports()
    if not result.headless_safe:
        raise RuntimeError("headless integrity command imported GUI modules: " + ", ".join(result.imported_gui_modules))
    return result


def assert_no_gui_modules_loaded() -> HeadlessSentinelResult:
    return assert_headless_integrity_safe()


def isolated_integrity_import_check(*, timeout_seconds: int = 20) -> HeadlessSentinelResult:
    """Evaluate integrity imports in a new interpreter, independent of the caller."""
    code_root = Path(__file__).resolve().parents[2]
    script = f'''
import importlib, json, sys
sys.path.insert(0, {str(code_root)!r})
baseline = set(sys.modules)
importlib.import_module("mac_audit_agent.integrity.__main__")
new = sorted(set(sys.modules) - baseline)
roots = {{"PySide6", "PyQt6", "PyQt5", "AppKit", "Cocoa", "objc", "tkinter"}}
bad = [name for name in new if name.split(".", 1)[0] in roots or name.startswith("mac_audit_agent.ui")]
print(json.dumps({{"headless_safe": not bad, "imported_gui_modules": bad}}))
'''
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=code_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        payload = json.loads(completed.stdout)
        if completed.returncode != 0:
            return HeadlessSentinelResult(False, [f"subprocess_exit_{completed.returncode}"])
        return HeadlessSentinelResult(bool(payload.get("headless_safe")), list(payload.get("imported_gui_modules", [])))
    except subprocess.TimeoutExpired:
        return HeadlessSentinelResult(False, ["integrity_import_subprocess_timeout"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return HeadlessSentinelResult(False, [f"integrity_import_subprocess_error:{type(exc).__name__}"])


__all__ = ["HeadlessSentinelResult", "assert_headless_integrity_safe", "assert_no_gui_modules_loaded", "isolated_integrity_import_check", "snapshot_headless_imports"]
