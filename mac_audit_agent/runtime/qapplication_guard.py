"""Final fail-closed gate immediately before QApplication construction."""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Any

from mac_audit_agent.runtime.gui_launch_modes import matching_crash_marker
from mac_audit_agent.runtime.macos_gui_preflight import MacOSGuiPreflightResult, run_macos_gui_preflight
from mac_audit_agent.runtime.gui_preflight import GuiPreflightResult, evaluate_gui_preflight


class ControlledStartupBlock(RuntimeError):
    """Raised before Qt/AppKit initialization when the GUI context is unsafe."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__("[%s] %s" % (code, reason))
        self.code = code
        self.reason = reason


def assert_qapplication_allowed(context: MacOSGuiPreflightResult | GuiPreflightResult | Any | None = None) -> MacOSGuiPreflightResult | GuiPreflightResult:
    if threading.current_thread() is not threading.main_thread():
        raise ControlledStartupBlock("GUI009_WRONG_THREAD", "QApplication must be constructed on the original process main thread.")
    if "PySide6.QtWidgets" in sys.modules:
        widgets=sys.modules["PySide6.QtWidgets"]
        if getattr(widgets,"QApplication").instance() is not None:
            raise ControlledStartupBlock("GUI008_GUI_ALREADY_INITIALIZED", "QApplication was initialized before the runtime boundary.")
    result = context if isinstance(context,(MacOSGuiPreflightResult,GuiPreflightResult)) else evaluate_gui_preflight()
    if not result.allowed:
        raise ControlledStartupBlock(result.failure_code or "GUI010_APPKIT_REGISTRATION_UNSAFE", getattr(result,"reason",getattr(result,"message","GUI preflight failed.")))
    if result.is_root:
        raise ControlledStartupBlock("GUIROOT001", "Do not create QApplication as root.")
    marker = matching_crash_marker(
        python_executable=result.python_executable,
        python_version=result.python_version,
        launch_mode=result.launch_mode,
    )
    if marker:
        raise ControlledStartupBlock("GUIQT001", "A matching prior GUI crash marker blocks this direct retry.")
    return result


__all__ = ["ControlledStartupBlock", "assert_qapplication_allowed"]
