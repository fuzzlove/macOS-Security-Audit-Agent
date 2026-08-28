from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from typing import Any


@dataclass
class ShutdownResult:
    graceful: bool
    steps: list[str]
    errors: list[str]


class AppShutdownCoordinator:
    def __init__(self, app: Any = None, window: Any = None, scheduler: Any = None, db: Any = None) -> None:
        self.app = app
        self.window = window
        self.scheduler = scheduler
        self.db = db
        self.shutting_down = False

    def install_signal_handlers(self) -> None:
        def handle_signal(received_signal: int, _frame: Any) -> None:
            self.request_shutdown(source=f"signal:{received_signal}")
            if self.app is not None and hasattr(self.app, "quit"):
                self.app.quit()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handle_signal)
            except Exception:
                pass

    def connect_qt(self) -> None:
        if self.app is not None and hasattr(self.app, "aboutToQuit"):
            self.app.aboutToQuit.connect(lambda: self.request_shutdown(source="QApplication.aboutToQuit"))

    def request_shutdown(self, *, source: str = "unknown") -> ShutdownResult:
        if self.shutting_down:
            return ShutdownResult(True, ["already_shutting_down"], [])
        self.shutting_down = True
        steps: list[str] = [f"source={source}", "set_shutting_down"]
        errors: list[str] = []
        window = self.window
        try:
            for timer_name in ("tray_status_timer", "cve_radar_timer", "investigation_autosave_timer"):
                timer = getattr(window, timer_name, None) if window is not None else None
                if timer is not None and hasattr(timer, "stop"):
                    timer.stop()
                    steps.append(f"stopped:{timer_name}")
        except Exception as exc:
            errors.append(f"timer_stop:{exc}")
        try:
            dialog = getattr(window, "_active_network_discovery_dialog", None) if window is not None else None
            if dialog is not None and hasattr(dialog, "cancel_scan"):
                dialog.cancel_scan()
                steps.append("cancelled_network_discovery")
        except Exception as exc:
            errors.append(f"cancel_dialog:{exc}")
        self._stop_window_workers(window, steps, errors)
        try:
            if self.scheduler is not None and hasattr(self.scheduler, "shutdown"):
                outcome = self.scheduler.shutdown(cancel=True, timeout_seconds=2.0)
                steps.append(f"scheduler_shutdown:{outcome}")
        except Exception as exc:
            errors.append(f"scheduler:{exc}")
        try:
            db = self.db or (getattr(window, "db", None) if window is not None else None)
            if db is not None:
                if hasattr(db, "set_background_monitor_state"):
                    db.set_background_monitor_state("gui_last_shutdown_source", source)
                if hasattr(db, "close"):
                    db.close()
                steps.append("db_closed")
        except Exception as exc:
            errors.append(f"db:{exc}")
        return ShutdownResult(not errors, steps, errors)

    @staticmethod
    def _stop_window_workers(window: Any, steps: list[str], errors: list[str]) -> None:
        if window is None:
            return
        # Feature widgets can have queued startup callbacks that have not yet
        # created their QThread.  Mark them as shutting down first so those
        # callbacks cannot start work after the generic QThread sweep.
        try:
            from PySide6.QtWidgets import QWidget

            for widget in window.findChildren(QWidget):
                shutdown = getattr(widget, "shutdown", None)
                if not callable(shutdown):
                    continue
                try:
                    outcome = shutdown()
                    steps.append(f"feature_shutdown:{type(widget).__name__}:{outcome}")
                except Exception as exc:
                    errors.append(f"feature_shutdown.{type(widget).__name__}:{exc}")
        except ImportError:
            pass
        except Exception as exc:
            errors.append(f"feature_shutdown:{exc}")
        # Stop feature-owned workers before closing shared resources such as the DB.
        for name in (
            "packet_capture_dialog",
            "_active_packet_capture_dialog",
            "_active_network_discovery_dialog",
        ):
            worker = getattr(window, name, None)
            if worker is None:
                continue
            for method_name in ("cancel_capture", "cancel_scan", "_stop_worker"):
                method = getattr(worker, method_name, None)
                if callable(method):
                    try:
                        method()
                        steps.append(f"stopped:{name}.{method_name}")
                    except Exception as exc:
                        errors.append(f"{name}.{method_name}:{exc}")
                    break
        try:
            from PySide6.QtCore import QThread, QThreadPool, QTimer
            from PySide6.QtWidgets import QDialog

            timers = window.findChildren(QTimer)
            for timer in timers:
                if timer.isActive():
                    timer.stop()
            if timers:
                steps.append(f"qt_timers_stopped:{len(timers)}")

            for dialog in window.findChildren(QDialog):
                if not dialog.isVisible():
                    continue
                for method_name in ("cancel_capture", "cancel_scan", "_stop_worker"):
                    method = getattr(dialog, method_name, None)
                    if callable(method):
                        try:
                            method()
                            steps.append(f"stopped_dialog:{type(dialog).__name__}.{method_name}")
                        except Exception as exc:
                            errors.append(f"dialog.{type(dialog).__name__}.{method_name}:{exc}")
                        break

            pool = QThreadPool.globalInstance()
            pool.clear()
            if pool.waitForDone(2000):
                steps.append("qt_thread_pool_stopped")
            else:
                errors.append("qt_thread_pool:workers exceeded 2000ms shutdown window")
            for thread in window.findChildren(QThread):
                if thread is QThread.currentThread() or not thread.isRunning():
                    continue
                thread.requestInterruption()
                thread.quit()
                if not thread.wait(2000):
                    # A running QObject slot cannot process quit(). At final app exit,
                    # terminate prevents QThread destruction from hanging/aborting.
                    thread.terminate()
                    if not thread.wait(500):
                        errors.append(f"qt_thread:{thread.objectName() or id(thread)} did not stop")
                    else:
                        steps.append(f"qt_thread_terminated:{thread.objectName() or id(thread)}")
                else:
                    steps.append(f"qt_thread_stopped:{thread.objectName() or id(thread)}")
        except ImportError:
            pass
        except Exception as exc:
            errors.append(f"qt_workers:{exc}")
        remaining = [thread.name for thread in threading.enumerate() if thread is not threading.current_thread() and not thread.daemon]
        if remaining:
            steps.append("remaining_non_daemon_threads:" + ",".join(sorted(remaining)))
