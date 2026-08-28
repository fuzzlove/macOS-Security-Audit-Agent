from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .support_matrix import RuntimeTier, classify_runtime


@dataclass(frozen=True)
class PythonSelection:
    mode: str; selected_executable: str; version: str; runtime_tier: str; suitable: bool; current_interpreter_selected: bool; reason: str; candidates_checked: tuple[str, ...]
    def to_dict(self) -> dict: return asdict(self)


def _probe(executable: str, *, require_qt: bool = False) -> Optional[dict]:
    code = (
        "import importlib.util,json,sys,platform; "
        "print(json.dumps({'version':list(sys.version_info[:3]),"
        "'implementation':sys.implementation.name,'architecture':platform.machine(),"
        "'gil':getattr(sys,'_is_gil_enabled',lambda:True)(),"
        "'pyside6':importlib.util.find_spec('PySide6') is not None,"
        "'shiboken6':importlib.util.find_spec('shiboken6') is not None}))"
    )
    try:
        result = subprocess.run([executable, "-c", code], capture_output=True, text=True, timeout=4, check=False)
        payload = json.loads(result.stdout) if result.returncode == 0 else None
        if require_qt and payload and not (payload.get("pyside6") and payload.get("shiboken6")):
            return None
        return payload
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError): return None


def _candidates(mode: str, root: Optional[Path]) -> list[str]:
    root = Path(root or Path.cwd())
    project = [root / ".venv/bin/python", root / ".venv-py313/bin/python", root / ".venv-py312/bin/python"]
    if mode in {"gui", "notifier", "release"}:
        names = ["python3.13", "python3.12", "python3.11", "python3.10", "python3"]
        raw = [*map(str, project), *names]
    elif mode == "daemon":
        raw = [*map(str, project), "python3.13", "python3.12", "python3.11", "python3.10", "python3.14", sys.executable, "/usr/bin/python3"]
    else:
        raw = [sys.executable, *map(str, project), "python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "/usr/bin/python3"]
    output: list[str] = []
    for item in raw:
        # Preserve virtual-environment launcher paths. Resolving their Python
        # symlink selects the base interpreter and silently drops the venv's
        # PySide6/Shiboken site-packages when launchd later executes it.
        found = os.path.abspath(item) if "/" in item and Path(item).exists() else shutil.which(item) or ""
        if found and found not in output: output.append(found)
    return output


def select_best_python_for_mode(mode: str, root: Optional[Path] = None) -> PythonSelection:
    checked: list[str] = []
    gui_mode = mode in {"gui", "notifier", "release"}
    for executable in _candidates(mode, root):
        checked.append(executable); probe = _probe(executable, require_qt=gui_mode)
        if not probe: continue
        support = classify_runtime(tuple(probe["version"]), system_python=executable == "/usr/bin/python3", standard_cpython=probe["implementation"] == "cpython" and probe["gil"])
        suitable = support.gui_allowed if gui_mode else support.headless_allowed or support.doctor_allowed
        if suitable:
            return PythonSelection(mode, executable, ".".join(map(str, probe["version"])), support.tier.value, True, os.path.realpath(executable) == os.path.realpath(sys.executable), support.reason, tuple(checked))
    return PythonSelection(mode, "", "", RuntimeTier.UNSUPPORTED.value, False, False, "No suitable interpreter was found. Use Python 3.12 or 3.13 for GUI, or Python 3.14 for headless diagnostics.", tuple(checked))


__all__ = ["PythonSelection", "select_best_python_for_mode"]
