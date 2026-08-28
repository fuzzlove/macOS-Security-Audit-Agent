from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class GuiExecutionContext:
    is_user_notifier_process: bool
    is_main_gui_app_process: bool
    is_system_daemon: bool
    is_cli_process: bool
    is_pre_uat_process: bool
    is_codex_or_terminal_process: bool
    has_qapplication_instance: bool
    can_create_qapplication: bool
    can_render_overlay: bool
    reason: str


def _has_qapplication_instance() -> bool:
    # Context inspection must never import Qt merely to ask whether the GUI is
    # running. A real GUI entry point will already have loaded QtWidgets.
    widgets=sys.modules.get("PySide6.QtWidgets")
    return bool(widgets and getattr(widgets,"QApplication").instance() is not None)


def detect_gui_execution_context(*, role: str = "") -> GuiExecutionContext:
    role_value = (role or os.environ.get("MAC_AUDIT_AGENT_MONITOR_ROLE", "")).strip().lower()
    argv = " ".join(sys.argv).lower()
    has_app = _has_qapplication_instance()
    is_user_notifier = role_value == "user-notifier" or "mac_audit_agent.user_notifier" in argv
    is_system_daemon = role_value == "system-daemon" or "--mode system-daemon" in argv
    is_pre_uat = "pre_uat_audit" in argv or "quality.pre_uat" in argv
    is_main_gui = has_app and ("mac_audit_agent.app" in argv or "main_window" in argv or role_value == "main-gui")
    is_codex_or_terminal = bool(os.environ.get("CODEX_HOME") or os.environ.get("TERM_PROGRAM") or os.environ.get("TERM"))
    is_cli = not is_user_notifier and not is_main_gui
    can_render = (is_user_notifier or is_main_gui) and not is_system_daemon
    if can_render:
        reason = "GUI rendering is allowed in user notifier/main GUI context."
    elif is_system_daemon:
        reason = "System daemon must route alerts through the user notifier."
    elif is_pre_uat:
        reason = "Pre-UAT must enqueue alert tests for the user notifier, not create GUI windows."
    else:
        reason = "CLI/Terminal/Codex context must route alerts through the user notifier."
    return GuiExecutionContext(
        is_user_notifier_process=is_user_notifier,
        is_main_gui_app_process=is_main_gui,
        is_system_daemon=is_system_daemon,
        is_cli_process=is_cli,
        is_pre_uat_process=is_pre_uat,
        is_codex_or_terminal_process=is_codex_or_terminal,
        has_qapplication_instance=has_app,
        can_create_qapplication=can_render,
        can_render_overlay=can_render,
        reason=reason,
    )


def ensure_overlay_render_allowed(*, role: str = "") -> tuple[bool, str]:
    context = detect_gui_execution_context(role=role)
    return context.can_render_overlay, context.reason


def ensure_action_gui_safe(action_type: str, *, role: str = "") -> tuple[bool, str]:
    context = detect_gui_execution_context(role=role)
    if action_type == "preserve_evidence_snapshot":
        return True, "Preserve Evidence Snapshot is headless-safe."
    if context.is_main_gui_app_process and context.has_qapplication_instance:
        return True, "Main GUI may handle GUI routes."
    if sys.version_info >= (3, 14) and not context.is_main_gui_app_process:
        return False, "Python 3.14 non-app GUI runtime detected; route must be queued for the main GUI."
    if context.is_user_notifier_process or context.is_system_daemon or context.is_cli_process:
        return False, "Non-main-GUI context must queue GUI actions instead of creating QApplication."
    return False, context.reason


def route_gui_action_or_queue(action_request):
    from mac_audit_agent.ui.routes import open_or_queue_timeline_route
    from mac_audit_agent.storage import AuditDatabase

    db_path = getattr(action_request, "source_db_path", "")
    if not db_path:
        raise ValueError("source_db_path is required to queue GUI actions")
    with AuditDatabase(Path(db_path).expanduser()) as db:  # type: ignore[name-defined]
        return open_or_queue_timeline_route(db, action_request)


from pathlib import Path

__all__ = [
    "GuiExecutionContext",
    "detect_gui_execution_context",
    "ensure_action_gui_safe",
    "ensure_overlay_render_allowed",
    "route_gui_action_or_queue",
]
