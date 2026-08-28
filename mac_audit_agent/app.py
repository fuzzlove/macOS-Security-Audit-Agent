from __future__ import annotations

import os
import shlex
import sqlite3
import sys
import tempfile
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.runtime.gui_preflight import require_gui_preflight

# This must remain before every Qt, AppKit, notification-bridge, and UI import.
_IMPORT_PREFLIGHT = require_gui_preflight()

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from mac_audit_agent.runtime.python_compat import current_python_gui_compatibility
from mac_audit_agent.runtime.single_instance import SingleInstanceLock
from mac_audit_agent.runtime.qapplication_guard import assert_qapplication_allowed
from mac_audit_agent.runtime.macos_foreground import activate_as_regular_application
from mac_audit_agent.ui.app_shutdown import AppShutdownCoordinator
from mac_audit_agent.ui.main_window import MainWindow, create_security_tray_icon
from mac_audit_agent.ui.integrity_diff_viewer import run_launch_integrity_gate
from mac_audit_agent.ui.startup_notice import preview_startup_notice
from mac_audit_agent.ui.eula_acceptance import EULA_VERSION, local_user_reference, require_current_eula_acceptance
from mac_audit_agent.ui.ethics_class import ETHICS_CURRICULUM_VERSION, mark_ethics_monitor_event_recorded, pending_ethics_monitor_event, require_ethics_completion
from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.version import APP_VERSION


def _record_eula_monitor_event(window) -> None:
    """Record acceptance in the existing monitor-event stream without alerting."""
    timestamp=datetime.now(timezone.utc).isoformat(); user_reference=local_user_reference()
    event=BackgroundMonitorEvent(
        event_id=f"eula-acceptance-{uuid4().hex}",timestamp=timestamp,event_type="governance_eula_accepted",
        severity="info",source="mission_governance",evidence=f"Draft EULA {EULA_VERSION} accepted for this application launch.",
        confidence="high",recommendation="Acceptance records software terms only and is not target authorization.",
        notification_sent=True,notification_decision="governance_log_only",notification_reason="EULA acceptance audit event; no security alert required",
        popup_allowed=False,metadata_json=json.dumps({"eula_version":EULA_VERSION,"application_version":APP_VERSION,"accepted_at":timestamp,"user_reference":user_reference},sort_keys=True),
    )
    window.db.record_monitor_event(event,dedupe_window_seconds=0)


def _record_pending_ethics_monitor_event(window) -> None:
    completion = pending_ethics_monitor_event()
    if not completion: return
    event = BackgroundMonitorEvent(
        event_id=f"ethics-completion-{uuid4().hex}", timestamp=str(completion["passed_at"]), event_type="governance_ethics_class_passed",
        severity="info", source="mission_governance", evidence=f"MSAA computer science ethics curriculum {ETHICS_CURRICULUM_VERSION} assessment passed.",
        confidence="high", recommendation="This records demonstrated basic curriculum understanding; it is not target authorization, certification, or proof of future conduct.",
        notification_sent=True, notification_decision="governance_log_only", notification_reason="One-time ethics completion audit event; no security alert required", popup_allowed=False,
        metadata_json=json.dumps({key: completion.get(key) for key in ("schema_version","curriculum_version","curriculum_sha256","passed_at","score_percent","user_reference","application_version","answers_recorded","authorization_granted")}, sort_keys=True),
    )
    if window.db.record_monitor_event(event,dedupe_window_seconds=0): mark_ethics_monitor_event_recorded()


def _run_governance_gates() -> bool:
    """Enforce launch order: preview, one-time ethics class, per-launch EULA."""
    return preview_startup_notice() and require_ethics_completion() and require_current_eula_acceptance()


def default_gui_db_path() -> Path:
    return Path.home() / ".mac_audit_agent.sqlite3"


def fallback_gui_db_path() -> Path:
    return Path.home() / ".mac_audit_agent" / "audit.sqlite3"


def emergency_gui_db_path() -> Path:
    return Path(tempfile.gettempdir()) / f"mac_audit_agent_{Path.home().name}" / "audit.sqlite3"


def _is_writable_database_open_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and any(
        marker in message
        for marker in (
            "readonly database",
            "read-only database",
            "unable to open database",
            "permission denied",
        )
    )


def _open_main_window_with_writable_db(db_path: Path) -> MainWindow:
    attempted: list[tuple[Path, str]] = []
    candidates: list[Path] = []
    for candidate in [db_path, fallback_gui_db_path(), emergency_gui_db_path()]:
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            window = MainWindow(candidate)
        except sqlite3.OperationalError as exc:
            if not _is_writable_database_open_error(exc):
                raise
            attempted.append((candidate, str(exc)))
            continue
        except OSError as exc:
            attempted.append((candidate, str(exc)))
            continue
        if attempted:
            details = "\n".join(f"- {path}: {error}" for path, error in attempted)
            QMessageBox.warning(
                window,
                "Database Is Not Writable",
                (
                    "MSAA could not open the normal database location for writing.\n\n"
                    f"{details}\n\n"
                    "MSAA started with this writable database instead:\n"
                    f"{candidate}\n\n"
                    "The original database files were left unchanged. Fix ownership or permissions if you want to use them again."
                ),
            )
        return window
    details = "\n".join(f"- {path}: {error}" for path, error in attempted)
    raise sqlite3.OperationalError(f"unable to open any writable MSAA database:\n{details}")


def _force_close_window_for_app_exit(window: MainWindow, *, source: str) -> None:
    try:
        window._force_quit_from_tray = True
        tray_icon = getattr(window, "tray_icon", None)
        if tray_icon is not None:
            tray_icon.hide()
        shutdown = getattr(window, "shutdown_coordinator", None)
        if shutdown is not None:
            shutdown.request_shutdown(source=source)
    finally:
        window.close()


def _admin_launch_command() -> str:
    if getattr(sys, "frozen", False):
        parts = [sys.executable, *sys.argv[1:]]
    else:
        script = Path(sys.argv[0]).resolve(strict=False)
        parts = [sys.executable, str(script), *sys.argv[1:]]
    return " ".join(shlex.quote(str(part)) for part in parts)


def _admin_required_for_launch() -> bool:
    if "--no-require-admin" in sys.argv:
        return False
    if "--require-admin" in sys.argv:
        return True
    value = os.environ.get("MSAA_REQUIRE_ADMIN_GUI", "")
    if value.strip().lower() in {"0", "false", "no", "off"}:
        return False
    if value.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    # The packaged GUI must remain a normal per-user Aqua application. System
    # monitoring and repairs use MSAA's separately authorized helper/services;
    # requiring the entire frozen GUI to run as root makes Finder launch and
    # the application's own root-GUI safety guard mutually incompatible.
    return False


def _show_admin_required_message(command: str) -> None:
    message = (
        "MSAA is configured to run with administrator privileges for this build.\n\n"
        "macOS does not provide a safe built-in way for this unsigned app to elevate itself without a privileged helper, "
        "and AppleScript elevation has been disabled.\n\n"
        "Launch it from Terminal with:\n\n"
        f"sudo {command}"
    )
    try:
        assert_qapplication_allowed()
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(None, "Administrator Privileges Required", message)
        app.processEvents()
    except Exception:
        pass
    sys.stderr.write(message + "\n")


def _enforce_admin_privileges() -> int | None:
    if not _admin_required_for_launch():
        return None
    if os.geteuid() == 0:
        return None
    _show_admin_required_message(_admin_launch_command())
    return 77


def main(*, preflight=None) -> int:
    debug_startup = os.environ.get("MSAA_DEBUG_STARTUP") == "1"
    trace = lambda message: print(f"MSAA startup: {message}", file=sys.stderr, flush=True) if debug_startup else None
    trace("entered GUI main")
    approved_context = assert_qapplication_allowed(preflight)
    admin_result = _enforce_admin_privileges()
    if admin_result is not None:
        return admin_result
    compatibility = current_python_gui_compatibility()
    if not compatibility.supported_for_gui:
        sys.stderr.write(
            "This action requires the MSAA GUI or user notifier. "
            "It cannot initialize GUI from this process.\n"
            f"{compatibility.reason}\n"
        )
        return 2
    single_instance = SingleInstanceLock.for_app()
    if not single_instance.acquire():
        requested = single_instance.request_activation()
        sys.stderr.write(
            "MSAA GUI is already running; requested its existing window be shown.\n"
            if requested else
            "MSAA GUI is already running; open it from the tray icon.\n"
        )
        return 0
    trace("single-instance lock acquired")
    assert_qapplication_allowed(approved_context)
    app = QApplication(sys.argv)
    trace("QApplication created")
    foreground_ok, foreground_reason = activate_as_regular_application()
    trace(f"macOS foreground activation: ok={foreground_ok} reason={foreground_reason}")
    try:
        if hasattr(app, "setWindowIcon"):
            app.setWindowIcon(create_security_tray_icon())
        if not _run_governance_gates():
            trace("startup notice declined")
            return 0
        trace("startup notice complete")
        db_path = default_gui_db_path()
        trace("constructing MainWindow")
        window = _open_main_window_with_writable_db(db_path)
        _record_pending_ethics_monitor_event(window)
        _record_eula_monitor_event(window)
        trace("MainWindow constructed")
        shutdown = AppShutdownCoordinator(app=app, window=window, scheduler=window.work_scheduler, db=window.db)
        shutdown.connect_qt()
        shutdown.install_signal_handlers()
        window.shutdown_coordinator = shutdown
        activation_timer = QTimer(window)
        activation_timer.setInterval(250)
        activation_timer.timeout.connect(
            lambda: window.restore_from_tray() if single_instance.consume_activation_request() else None
        )
        activation_timer.start()
        window.instance_activation_timer = activation_timer
        # Present the owner window before any launch-time modal gate. On macOS,
        # a modal dialog whose parent has never been shown can exist behind the
        # launching Terminal while the already-created tray icon remains visible.
        window.show()
        activate_as_regular_application()
        window.restore_from_tray()
        app.processEvents()
        trace("main window shown; scheduling integrity gate")

        def evaluate_integrity_after_event_loop_start() -> None:
            trace("evaluating integrity gate on primary event loop")
            allowed = run_launch_integrity_gate(parent=window, db=window.db)
            if not allowed:
                trace("integrity gate rejected")
                _force_close_window_for_app_exit(window, source="launch_integrity_gate_failed")
                app.quit()
                return
            trace("integrity gate accepted")
            window.initialize_tray_icon()
            window.restore_from_tray()

        # Cocoa window registration is not fully usable until the primary Qt
        # event loop starts. Opening a nested modal loop before app.exec() can
        # leave the dialog undiscoverable while its tray icon remains visible.
        QTimer.singleShot(0, evaluate_integrity_after_event_loop_start)
        trace("entering Qt event loop")
        return app.exec()
    finally:
        window_instance = locals().get("window")
        if window_instance is not None:
            coordinator = getattr(window_instance, "shutdown_coordinator", None)
            if coordinator is not None:
                coordinator.request_shutdown(source="app_finally")
        single_instance.release()


if __name__ == "__main__":
    raise SystemExit(main())
