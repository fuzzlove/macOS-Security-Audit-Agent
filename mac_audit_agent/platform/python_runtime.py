from __future__ import annotations

import os
import platform
import sys
from dataclasses import asdict, dataclass

from mac_audit_agent.runtime.support_matrix import classify_runtime


@dataclass(frozen=True)
class PythonRuntimeDetails:
    version: str; implementation: str; executable: str; architecture: str; virtual_environment: bool; system_python: bool; homebrew_python: bool; runtime_tier: str; gui_allowed: bool; headless_allowed: bool; doctor_allowed: bool
    def to_dict(self) -> dict[str, object]: return asdict(self)


def detect_python_details() -> PythonRuntimeDetails:
    executable = os.path.realpath(sys.executable); lower = executable.lower()
    system = executable == "/usr/bin/python3" or "/library/developer/commandlinetools/" in lower or "/system/library/" in lower
    homebrew = "/opt/homebrew/" in lower or "/usr/local/cellar/" in lower or "/usr/local/opt/" in lower
    support = classify_runtime(tuple(sys.version_info[:3]), system_python=system, standard_cpython=sys.implementation.name == "cpython" and getattr(sys, "_is_gil_enabled", lambda: True)())
    return PythonRuntimeDetails(platform.python_version(), sys.implementation.name, executable, platform.machine(), sys.prefix != getattr(sys, "base_prefix", sys.prefix), system, homebrew, support.tier.value, support.gui_allowed, support.headless_allowed, support.doctor_allowed)


__all__ = ["PythonRuntimeDetails", "detect_python_details"]
