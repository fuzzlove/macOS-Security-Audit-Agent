from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from enum import Enum


class RuntimeTier(str, Enum):
    FULL = "tier_a_full_gui_cli"
    HEADLESS = "tier_b_headless_cli"
    DOCTOR = "tier_c_doctor_only"
    EXPERIMENTAL = "tier_d_experimental"
    UNSUPPORTED = "tier_d_unsupported"


@dataclass(frozen=True)
class RuntimeSupport:
    tier: RuntimeTier
    gui_allowed: bool
    headless_allowed: bool
    doctor_allowed: bool
    supported_modes: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict:
        value = asdict(self); value["tier"] = self.tier.value; return value


def classify_runtime(version: tuple[int, ...], *, system_python: bool = False, standard_cpython: bool = True) -> RuntimeSupport:
    major_minor = tuple(version[:2])
    experimental = os.environ.get("MSAA_ALLOW_EXPERIMENTAL_PY314_GUI", "").strip() == "1"
    if not standard_cpython:
        return RuntimeSupport(RuntimeTier.UNSUPPORTED, False, False, False, (), "This Python runtime is unsupported. Use standard CPython 3.12 or 3.13.")
    if major_minor <= (3, 9) or system_python:
        return RuntimeSupport(RuntimeTier.DOCTOR, False, False, True, ("doctor", "bootstrap"), "Python 3.9 and older runtimes are deprecated and limited to doctor diagnostics. Use Python 3.12 or 3.13 for the GUI, or Python 3.10-3.14 for supported headless operation.")
    if (3, 10) <= major_minor <= (3, 13):
        return RuntimeSupport(RuntimeTier.FULL, True, True, True, ("gui", "notifier", "daemon", "cli", "doctor", "integrity", "protection", "release"), "Validated full GUI and CLI runtime.")
    if major_minor == (3, 14):
        gui = experimental
        return RuntimeSupport(RuntimeTier.HEADLESS, gui, True, True, ("doctor", "daemon", "cli", "integrity", "protection"), "Headless diagnostics are supported; GUI is not validated for this Python version." if not gui else "Experimental Python 3.14 GUI override is active.")
    if major_minor >= (3, 15):
        return RuntimeSupport(RuntimeTier.EXPERIMENTAL, False, True, True, ("doctor", "runtime_diagnostics"), "This newer Python runtime is experimental and limited to diagnostics until explicitly validated.")
    return RuntimeSupport(RuntimeTier.UNSUPPORTED, False, False, False, (), "Unsupported Python runtime.")


__all__ = ["RuntimeSupport", "RuntimeTier", "classify_runtime"]
