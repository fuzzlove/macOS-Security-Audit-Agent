from __future__ import annotations

import importlib.util
import os
import platform
import site
import subprocess
import sys
from dataclasses import asdict, dataclass

from .support_matrix import classify_runtime


@dataclass(frozen=True)
class PythonRuntimeInfo:
    executable: str; version: str; version_tuple: tuple[int, ...]; implementation: str; architecture: str; platform: str; macos_version: str
    is_homebrew: bool; is_system_python: bool; is_framework_python: bool; is_venv: bool; is_conda: bool; is_pyenv: bool
    has_pip: bool; has_venv: bool; has_ensurepip: bool; has_ssl: bool; has_sqlite3: bool; has_tkinter: bool
    site_packages_paths: tuple[str, ...]; sys_path: tuple[str, ...]; runtime_tier: str; gui_allowed: bool; headless_allowed: bool; recommended_action: str

    def to_dict(self) -> dict: return asdict(self)


def _available(module: str) -> bool:
    try: return importlib.util.find_spec(module) is not None
    except (ImportError, AttributeError, ValueError): return False


def _pip_works() -> bool:
    if not _available("pip"): return False
    try: return subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, timeout=4, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError): return False


def detect_python_runtime() -> PythonRuntimeInfo:
    executable = os.path.realpath(sys.executable)
    lower = executable.lower()
    homebrew = any(marker in lower for marker in ("/opt/homebrew/", "/usr/local/cellar/", "/usr/local/opt/"))
    system = executable == "/usr/bin/python3" or any(marker in executable for marker in ("/System/Library/", "/Library/Developer/CommandLineTools/"))
    support = classify_runtime(tuple(sys.version_info[:3]), system_python=system, standard_cpython=sys.implementation.name == "cpython" and getattr(sys, "_is_gil_enabled", lambda: True)())
    recommended = "No runtime change required." if support.gui_allowed else "Use Python 3.12 or 3.13 for GUI mode; this interpreter remains useful for doctor/headless commands." if support.headless_allowed else "Use this interpreter only for doctor/bootstrap, and use Python 3.12 or 3.13 for MSAA features." if support.doctor_allowed else "Install standard CPython 3.12 or 3.13."
    try: site_paths = tuple(site.getsitepackages())
    except (AttributeError, OSError): site_paths = ()
    return PythonRuntimeInfo(executable, platform.python_version(), tuple(sys.version_info[:3]), sys.implementation.name, platform.machine(), platform.platform(), platform.mac_ver()[0], homebrew, system, ".framework/" in lower, sys.prefix != getattr(sys, "base_prefix", sys.prefix), bool(os.environ.get("CONDA_PREFIX")), ".pyenv/" in lower, _pip_works(), _available("venv"), _available("ensurepip"), _available("ssl"), _available("sqlite3"), _available("tkinter"), site_paths, tuple(sys.path), support.tier.value, support.gui_allowed, support.headless_allowed, recommended)


__all__ = ["PythonRuntimeInfo", "detect_python_runtime"]
