from __future__ import annotations

import os
import platform
import sys
from dataclasses import asdict, dataclass


@dataclass
class PythonRuntimeGateResult:
    python_executable: str
    python_version: str
    supported_for_integrity_cli: bool
    supported_for_gui: bool
    unsupported_reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_python_runtime() -> PythonRuntimeGateResult:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    gil_enabled = getattr(sys, "_is_gil_enabled", lambda: True)()
    standard_cpython = sys.implementation.name == "cpython" and gil_enabled
    experimental_py314 = os.environ.get("MSAA_ALLOW_EXPERIMENTAL_PY314_GUI", "").strip() == "1"
    gui_supported = (3, 10) <= sys.version_info[:2] <= (3, 13) and standard_cpython
    if sys.version_info[:2] == (3, 14) and standard_cpython and experimental_py314:
        gui_supported = True
    cli_supported = sys.version_info[:2] >= (3, 10)
    reason = ""
    if sys.version_info[:2] == (3, 14) and standard_cpython and not experimental_py314:
        reason = "MSAA GUI mode is not validated for Python 3.14. Use Python 3.12 or 3.13 for the GUI, or run headless diagnostics with --doctor. Set MSAA_ALLOW_EXPERIMENTAL_PY314_GUI=1 only for explicit compatibility testing."
    elif sys.version_info[:2] == (3, 14) and not standard_cpython:
        reason = "The free-threaded Python 3.14 ABI is not yet qualified; use the standard GIL-enabled MSAA build."
    elif sys.version_info[:2] == (3, 9):
        reason = "Python 3.9 is deprecated doctor-only; use Python 3.12 or 3.13 for the GUI and production services."
    elif not cli_supported:
        reason = "Python runtime is too old for MSAA integrity tooling."
    return PythonRuntimeGateResult(sys.executable, version, cli_supported, gui_supported, reason)


__all__ = ["PythonRuntimeGateResult", "evaluate_python_runtime"]
