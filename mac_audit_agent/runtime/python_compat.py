from __future__ import annotations

import os
import sys
from dataclasses import dataclass


SUPPORTED_GUI_PYTHONS = frozenset({(3, 12), (3, 13)})


@dataclass(frozen=True)
class PythonGuiCompatibility:
    executable: str
    version: str
    supported_for_gui: bool
    reason: str


def current_python_gui_compatibility() -> PythonGuiCompatibility:
    info = sys.version_info
    version = f"{info.major}.{info.minor}.{info.micro}"
    supported = (info.major, info.minor) in SUPPORTED_GUI_PYTHONS
    reason = (
        "Python GUI runtime is in the supported MSAA range."
        if supported
        else "MSAA detected Python %s. Only Python 3.12 and 3.13 are validated for the GUI; use headless diagnostics with --doctor." % version
    )
    return PythonGuiCompatibility(sys.executable, version, supported, reason)


def require_supported_gui_python() -> None:
    """Fail early with a controlled error when the GUI runtime is unsupported."""
    compatibility = current_python_gui_compatibility()
    if not compatibility.supported_for_gui:
        raise RuntimeError(
            "MSAA GUI requires validated CPython 3.12 or 3.13; "
            f"detected {compatibility.version}."
        )


__all__ = ["PythonGuiCompatibility", "current_python_gui_compatibility", "require_supported_gui_python"]
