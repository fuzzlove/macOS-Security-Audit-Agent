from __future__ import annotations

import os
from dataclasses import dataclass

from mac_audit_agent.runtime.execution_context import ExecutionContext, detect_execution_context


class UnsafeGuiImportError(RuntimeError):
    def __init__(self, attempted_module: str, execution_context: ExecutionContext, reason: str) -> None:
        self.attempted_module = attempted_module
        self.execution_context = execution_context
        self.reason = reason
        self.recommended_fix = "Route this work through the main GUI/user notifier, or use a static/headless service."
        super().__init__(
            "Unsafe GUI import blocked. This command is running in a headless/CLI context and must not initialize Qt/AppKit. "
            f"attempted_module={attempted_module}; reason={reason}; recommended_fix={self.recommended_fix}"
        )


def assert_gui_import_allowed(reason: str) -> None:
    context = detect_execution_context()
    if _unsafe_override_allowed(context):
        return
    if not context.can_import_gui:
        raise UnsafeGuiImportError("gui", context, reason or context.reason)


def assert_qapplication_allowed(reason: str) -> None:
    context = detect_execution_context()
    if _unsafe_override_allowed(context):
        return
    if not context.can_create_qapplication:
        raise UnsafeGuiImportError("QApplication", context, reason or context.reason)


def guard_gui_import(module_name: str) -> None:
    context = detect_execution_context()
    if _unsafe_override_allowed(context):
        return
    if not context.can_import_gui:
        raise UnsafeGuiImportError(module_name, context, context.reason)


def _unsafe_override_allowed(context: ExecutionContext) -> bool:
    if os.environ.get("MSAA_ALLOW_UNSAFE_GUI_IMPORT") != "1":
        return False
    if context.running_pre_uat or context.running_integrity_cli or context.running_release_verify:
        return False
    return True


__all__ = ["UnsafeGuiImportError", "assert_gui_import_allowed", "assert_qapplication_allowed", "guard_gui_import"]
