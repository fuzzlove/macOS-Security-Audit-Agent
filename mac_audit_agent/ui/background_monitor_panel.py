from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.launch_agent import LaunchAgentManager, default_launch_agent_paths, runtime_monitor_script_path, runtime_root
from mac_audit_agent.monitor import (
    DISCLAIMER,
    FALLBACK_MONITOR_LOG,
    BackgroundMonitorService,
    HEARTBEAT_SECONDS,
    STDERR_MONITOR_LOG,
    append_monitor_log_line,
    clear_monitor_log_files,
    is_heartbeat_fresh,
    is_pid_alive,
    tail_text_file,
)
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.reporting import export_monitor_events_html, export_monitor_events_json, get_reports_dir
from mac_audit_agent.storage import AuditDatabase

LOGGER = logging.getLogger(__name__)


EVENT_TYPES = [
    "",
    "camera_activity_suspected",
    "camera_activity_confirmed",
    "microphone_activity_suspected",
    "capture_capable_process_observed",
    "capture_capable_process_closed",
    "capture_process_observed",
    "suspicious_process_observed",
    "screen_wake",
    "screen_sleep",
    "display_sleep",
    "display_wake",
    "system_wake",
    "system_sleep",
    "screen_locked",
    "screen_unlocked",
    "session_locked",
    "session_unlocked",
    "clamshell_state_changed",
    "possible_lid_closed",
    "possible_lid_opened",
    "lid_closed",
    "lid_opened",
    "screen_sharing_enabled",
    "screen_sharing_disabled",
    "remote_login_enabled",
    "screen_recording_permission_present",
    "persistence_item_created",
    "localhost_hidden_port_detected",
    "new_admin_user_detected",
    "packet_capture_started",
    "packet_capture_completed",
    "major_security_event",
    "monitor_self_test",
    "monitor_test_event",
]


class BackgroundMonitorPanel(QWidget):
    def __init__(self, db: AuditDatabase, launch_agent: LaunchAgentManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self.launch_agent = launch_agent
        self.service = BackgroundMonitorService(self.db.path, record_startup=False)
        self.notifications = NotificationManager(self.db)
        self._build_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(5000)
        self.refresh()

    def _fallback_log_path_text(self) -> str:
        return str(FALLBACK_MONITOR_LOG.expanduser().resolve())

    def _stderr_log_path(self) -> Path:
        stderr_path = getattr(getattr(self.launch_agent, "paths", None), "stderr_path", STDERR_MONITOR_LOG)
        return Path(stderr_path).expanduser()

    def _import_failure_message(self, stderr_tail: str) -> str:
        if "ModuleNotFoundError: No module named 'mac_audit_agent'" not in stderr_tail:
            return ""
        return (
            "LaunchAgent Python import failed: ModuleNotFoundError: No module named 'mac_audit_agent'. "
            "Fix: reinstall the monitor so it runs from ~/.mac_audit_agent/runtime instead of a protected Documents folder."
        )

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.status_label = QLabel("Status: unknown")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        disclaimer = QLabel(DISCLAIMER)
        disclaimer.setWordWrap(True)
        layout.addWidget(disclaimer)

        controls = QHBoxLayout()
        self.install_button = QPushButton("Install Background Monitor")
        self.repair_button = QPushButton("Repair Background Monitor")
        self.force_reinstall_button = QPushButton("Force Reinstall Monitor")
        self.restart_button = QPushButton("Restart Monitor")
        self.start_button = QPushButton("Start Monitor")
        self.stop_button = QPushButton("Stop Monitor")
        self.uninstall_button = QPushButton("Uninstall Monitor")
        self.show_logs_button = QPushButton("Show Monitor Logs")
        self.clear_logs_button = QPushButton("Clear Monitor Logs")
        self.test_notification_button = QPushButton("Test Notification")
        self.test_dialog_button = QPushButton("Test High Priority Dialog")
        self.test_silent_event_button = QPushButton("Test Silent Log Event")
        self.test_event_button = QPushButton("Generate Test Event")
        self.event_priorities_button = QPushButton("Event Priorities")
        for widget in [
            self.install_button,
            self.repair_button,
            self.force_reinstall_button,
            self.restart_button,
            self.start_button,
            self.stop_button,
            self.uninstall_button,
            self.show_logs_button,
            self.clear_logs_button,
            self.test_notification_button,
            self.test_dialog_button,
            self.test_silent_event_button,
            self.test_event_button,
            self.event_priorities_button,
        ]:
            controls.addWidget(widget)
        layout.addLayout(controls)

        settings_layout = QGridLayout()
        settings_layout.addWidget(QLabel("Enable Continuous Monitoring"), 0, 0)
        self.continuous_monitoring_checkbox = QCheckBox()
        settings_layout.addWidget(self.continuous_monitoring_checkbox, 0, 1)
        settings_layout.addWidget(QLabel("Start at Login"), 0, 2)
        self.start_at_login_checkbox = QCheckBox()
        settings_layout.addWidget(self.start_at_login_checkbox, 0, 3)
        settings_layout.addWidget(QLabel("Popup only critical events"), 0, 4)
        self.popup_only_severe_checkbox = QCheckBox()
        self.popup_only_severe_checkbox.setChecked(True)
        settings_layout.addWidget(self.popup_only_severe_checkbox, 0, 5)
        settings_layout.addWidget(QLabel("Alert on browser camera-capable processes"), 0, 6)
        self.browser_capture_popup_checkbox = QCheckBox()
        self.browser_capture_popup_checkbox.setChecked(False)
        settings_layout.addWidget(self.browser_capture_popup_checkbox, 0, 7)
        self.notify_all_checkbox = QCheckBox()
        self.notify_all_checkbox.setChecked(False)
        settings_layout.addWidget(self.notify_all_checkbox, 1, 1)
        settings_layout.addWidget(QLabel("Notify All Events"), 1, 0)
        settings_layout.addWidget(QLabel("Notify Important Events"), 1, 2)
        self.notify_important_checkbox = QCheckBox()
        self.notify_important_checkbox.setChecked(True)
        settings_layout.addWidget(self.notify_important_checkbox, 1, 3)
        settings_layout.addWidget(QLabel("Notify Min Severity"), 1, 4)
        self.notify_min_severity_combo = QComboBox()
        for severity in ["info", "low", "medium", "high", "critical"]:
            self.notify_min_severity_combo.addItem(severity, severity)
        settings_layout.addWidget(self.notify_min_severity_combo, 1, 5)
        settings_layout.addWidget(QLabel("Duplicate Rate Limit Seconds"), 1, 8)
        self.rate_limit_input = QLineEdit("10")
        settings_layout.addWidget(self.rate_limit_input, 1, 9)
        settings_layout.addWidget(QLabel("Notification Mode"), 1, 10)
        self.notification_mode_combo = QComboBox()
        for mode in ["notification", "dialog", "both"]:
            self.notification_mode_combo.addItem(mode, mode)
        settings_layout.addWidget(self.notification_mode_combo, 1, 11)
        settings_layout.addWidget(QLabel("Notification Sound"), 1, 12)
        self.notification_sound_input = QLineEdit("Glass")
        settings_layout.addWidget(self.notification_sound_input, 1, 13)
        self.save_settings_button = QPushButton("Save Notification Settings")
        settings_layout.addWidget(self.save_settings_button, 1, 14)
        layout.addLayout(settings_layout)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Event Type"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All", "")
        for event_type in EVENT_TYPES[1:]:
            self.filter_combo.addItem(event_type, event_type)
        filters.addWidget(self.filter_combo)
        self.export_json_button = QPushButton("Export Monitor Log JSON")
        self.export_html_button = QPushButton("Export Monitor Log HTML")
        filters.addWidget(self.export_json_button)
        filters.addWidget(self.export_html_button)
        filters.addStretch(1)
        layout.addLayout(filters)

        self.events_table = QTableWidget(0, 7)
        self.events_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Severity", "Source", "Process", "Confidence", "Evidence"])
        self.events_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.events_table)

        layout.addWidget(QLabel("Show Monitor Health"))
        self.health_panel = QTextEdit()
        self.health_panel.setReadOnly(True)
        layout.addWidget(self.health_panel)

        layout.addWidget(QLabel("What am I looking at?"))
        self.explanation = QTextEdit()
        self.explanation.setReadOnly(True)
        self.explanation.setPlainText(
            "This panel shows local privacy indicators and session state transitions recorded by the optional user-session LaunchAgent. "
            "Entries are conservative: suspected events come from correlation, not proof of capture. "
            "The monitor does not record camera images, microphone audio, screen contents, keystrokes, or packet contents."
        )
        layout.addWidget(self.explanation)

        self.install_button.clicked.connect(self.install_monitor)
        self.repair_button.clicked.connect(self.repair_monitor)
        self.force_reinstall_button.clicked.connect(self.force_reinstall_monitor)
        self.restart_button.clicked.connect(self.restart_monitor)
        self.start_button.clicked.connect(self.start_monitor)
        self.stop_button.clicked.connect(self.stop_monitor)
        self.uninstall_button.clicked.connect(self.uninstall_monitor)
        self.show_logs_button.clicked.connect(self.show_logs)
        self.clear_logs_button.clicked.connect(self.clear_monitor_logs)
        self.test_notification_button.clicked.connect(self.test_notification)
        self.test_dialog_button.clicked.connect(self.test_high_priority_dialog)
        self.test_silent_event_button.clicked.connect(self.test_silent_log_event)
        self.test_event_button.clicked.connect(self.generate_test_event)
        self.event_priorities_button.clicked.connect(self.show_event_priorities_dialog)
        self.save_settings_button.clicked.connect(self.save_notification_settings)
        self.continuous_monitoring_checkbox.toggled.connect(self.toggle_continuous_monitoring)
        self.start_at_login_checkbox.toggled.connect(self.toggle_start_at_login)
        self.filter_combo.currentIndexChanged.connect(self.refresh_events)
        self.export_json_button.clicked.connect(self.export_json)
        self.export_html_button.clicked.connect(self.export_html)

    def refresh(self) -> None:
        launch_status = self.launch_agent.status()
        db_status = self.db.get_background_monitor_status()
        installed = launch_status.installed or db_status.installed
        loaded = launch_status.loaded if installed else db_status.loaded
        process_pid = launch_status.process_pid or db_status.process_pid
        pid_alive = is_pid_alive(process_pid)
        orphan_process = bool(pid_alive and not loaded)
        heartbeat_fresh = is_heartbeat_fresh(db_status.last_heartbeat, max_age_seconds=max(120, HEARTBEAT_SECONDS * 2))
        running = pid_alive or heartbeat_fresh
        stderr_tail = tail_text_file(self._stderr_log_path(), lines=30)
        import_failure = ""
        if loaded and not pid_alive and not heartbeat_fresh:
            import_failure = self._import_failure_message(stderr_tail)
        last_error = import_failure or db_status.last_error or launch_status.last_error or "none"
        if loaded and not pid_alive and not heartbeat_fresh:
            status_text = "loaded but crashed or exited"
        elif not loaded and pid_alive:
            status_text = "orphan monitor process"
        elif pid_alive and not launch_status.running:
            status_text = "running; launchctl state parse uncertain"
        elif running:
            status_text = "running"
        else:
            status_text = "stopped"
        if loaded and heartbeat_fresh and db_status.detector_last_run_timestamp:
            status_text = "healthy"
        elif heartbeat_fresh and not db_status.detector_last_run_timestamp:
            status_text = "degraded: heartbeat without detector loop"
        if import_failure:
            status_text = "loaded but crashed or exited"
        stale_text = "\nMonitor is installed but not actively running." if loaded and not running else ""
        if not loaded and pid_alive:
            stale_text = "\nMonitor process is running outside LaunchAgent. Repair recommended."
        elif installed and not heartbeat_fresh:
            stale_text = "\nMonitor not healthy. Restart Monitor is recommended."
        self.status_label.setText(
            f"Status: {status_text} | Installed: {'yes' if installed else 'no'} | Loaded: {'yes' if loaded else 'no'}\n"
            f"Plist: {launch_status.plist_path or db_status.plist_path}\n"
            f"Last heartbeat: {db_status.last_heartbeat or 'none'}\n"
            f"Last event: {db_status.last_event_timestamp or 'none'}\n"
            f"PID: {process_pid or 'none'}\n"
            f"Last error: {last_error}{stale_text}"
        )
        self.health_panel.setPlainText(
            "\n".join(
                [
                    f"LaunchAgent installed: {'yes' if installed else 'no'}",
                    f"LaunchAgent loaded: {'yes' if loaded else 'no'}",
                    f"Monitor running: {'yes' if running else 'no'}",
                    f"Monitor status: {status_text}",
                    f"Monitor process PID: {process_pid or 'none'}",
                    f"PID alive: {'yes' if pid_alive else 'no'}",
                    f"Orphan process: {'yes' if orphan_process else 'no'}",
                    f"Log DB path: {db_status.db_path or self.db.path}",
                    f"Last heartbeat timestamp: {db_status.last_heartbeat or 'none'}",
                    f"Heartbeat fresh: {'yes' if heartbeat_fresh else 'no'}",
                    f"Last event timestamp: {db_status.last_event_timestamp or 'none'}",
                    f"Last error: {last_error}",
                    f"Detector errors: {db_status.detector_errors or 'none'}",
                    f"Detector last run timestamp: {db_status.detector_last_run_timestamp or 'none'}",
                    f"Detector last run counts: {db_status.detector_last_run_counts or '{}'}",
                    f"Detector enabled camera: {'yes' if db_status.detector_enabled_camera else 'no'}",
                    f"Detector enabled session: {'yes' if db_status.detector_enabled_session else 'no'}",
                    f"Detector enabled sharing: {'yes' if db_status.detector_enabled_sharing else 'no'}",
                    f"Detector enabled process: {'yes' if db_status.detector_enabled_process else 'no'}",
                    f"Detector last zero reason: {db_status.detector_last_zero_reason or 'none'}",
                    f"Current snapshot: {db_status.current_snapshot or '{}'}",
                    f"Current snapshot keys: {', '.join(sorted(json.loads(db_status.current_snapshot or '{}').keys())) if db_status.current_snapshot else 'none'}",
                    f"Events in last 10 minutes: {db_status.events_last_10_minutes}",
                    f"Suppressed popup count: {self._suppressed_popup_count()}",
                    f"Last notification decision: {self._last_notification_decision()}",
                    f"Notification permission/status: {db_status.notification_status or self.notifications.status()}",
                    f"Current launchctl domain: {launch_status.current_launchctl_domain or db_status.current_launchctl_domain or 'unknown'}",
                    f"Log path: {self._fallback_log_path_text()}",
                    f"Fallback log path: {self._fallback_log_path_text()}",
                    f"Runtime path: {runtime_root()}",
                    "Monitor runtime installed outside protected Documents folder.",
                    f"Stderr log path: {self._stderr_log_path()}",
                    f"Stderr tail:\n{stderr_tail or 'none'}",
                ]
            )
        )
        settings = self.notifications.settings()
        self.continuous_monitoring_checkbox.blockSignals(True)
        self.start_at_login_checkbox.blockSignals(True)
        self.continuous_monitoring_checkbox.setChecked(bool(loaded or running or heartbeat_fresh))
        self.start_at_login_checkbox.setChecked(bool(installed))
        self.continuous_monitoring_checkbox.blockSignals(False)
        self.start_at_login_checkbox.blockSignals(False)
        self.notify_all_checkbox.setChecked(bool(settings["notify_all_events"]))
        self.notify_important_checkbox.setChecked(bool(settings["notify_important_events"]))
        self.popup_only_severe_checkbox.setChecked(bool(settings.get("popup_only_severe_events", True)))
        self.browser_capture_popup_checkbox.setChecked(bool(settings.get("browser_capture_process_popup", False)))
        current_severity = str(settings["notify_min_severity"])
        index = self.notify_min_severity_combo.findData(current_severity)
        if index >= 0:
            self.notify_min_severity_combo.setCurrentIndex(index)
        mode_index = self.notification_mode_combo.findData(str(settings.get("notification_mode", "notification")))
        if mode_index >= 0:
            self.notification_mode_combo.setCurrentIndex(mode_index)
        self.rate_limit_input.setText(str(settings["duplicate_rate_limit_seconds"]))
        self.notification_sound_input.setText(str(settings["notification_sound"]))
        self.start_button.setEnabled(installed)
        self.stop_button.setEnabled(installed)
        self.uninstall_button.setEnabled(installed)
        self.restart_button.setEnabled(bool(installed))
        self.refresh_events()

    def refresh_events(self) -> None:
        event_type = str(self.filter_combo.currentData() or "")
        events = self.db.latest_monitor_events(limit=200) if not event_type else self.db.recent_background_monitor_events(limit=200, event_type=event_type)
        self.events_table.setRowCount(0)
        if not events:
            self.events_table.setRowCount(1)
            self.events_table.setItem(0, 0, QTableWidgetItem("No recent events"))
            for column in range(1, self.events_table.columnCount()):
                self.events_table.setItem(0, column, QTableWidgetItem(""))
            self.events_table.resizeRowsToContents()
            return
        for event in events:
            row = self.events_table.rowCount()
            self.events_table.insertRow(row)
            for column, value in enumerate(
                [
                    event.timestamp,
                    event.event_type,
                    event.severity,
                    event.source,
                    event.process_name,
                    event.confidence,
                    event.evidence,
                ]
            ):
                self.events_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.events_table.resizeRowsToContents()

    def install_monitor(self) -> None:
        if QMessageBox.question(self, "Install Background Monitor", DISCLAIMER) != QMessageBox.StandardButton.Yes:
            return
        try:
            plist_path = self.launch_agent.install()
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("enabled", "1")
            self.db.set_background_monitor_state("loaded", "0")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("label", self.launch_agent.status().label)
            self.db.set_background_monitor_state("log_path", self.launch_agent.show_logs())
            self.db.set_background_monitor_state("db_path", str(self.db.path))
            self.db.set_background_monitor_state("current_launchctl_domain", self.launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Install Failed", str(exc))
        self.refresh()

    def toggle_continuous_monitoring(self, enabled: bool) -> None:
        try:
            if enabled:
                if not self.launch_agent.status().installed:
                    self.launch_agent.install()
                self.launch_agent.start()
                deadline = time.monotonic() + 10
                heartbeat_updated = False
                detector_updated = False
                baseline = self.db.get_background_monitor_status()
                while time.monotonic() < deadline:
                    current = self.db.get_background_monitor_status()
                    heartbeat_updated = bool(current.last_heartbeat and current.last_heartbeat != baseline.last_heartbeat)
                    detector_updated = bool(current.detector_last_run_timestamp and current.detector_last_run_timestamp != baseline.detector_last_run_timestamp)
                    if heartbeat_updated and detector_updated:
                        break
                    time.sleep(1)
                self.db.set_background_monitor_state("enabled", "1")
                if not (heartbeat_updated and detector_updated):
                    QMessageBox.warning(
                        self,
                        "Continuous Monitoring",
                        "LaunchAgent started, but heartbeat or detector loop did not update within 10 seconds.",
                    )
            else:
                self.launch_agent.stop()
                self.db.set_background_monitor_state("running", "0")
                self.db.set_background_monitor_state("loaded", "0")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Continuous Monitoring Failed", str(exc))
        self.refresh()

    def toggle_start_at_login(self, enabled: bool) -> None:
        try:
            if enabled:
                self.launch_agent.install()
                self.db.set_background_monitor_state("installed", "1")
                self.db.set_background_monitor_state("enabled", "1")
            else:
                try:
                    self.launch_agent.stop()
                except Exception:
                    pass
                self.launch_agent.uninstall()
                for key, value in [("installed", "0"), ("enabled", "0"), ("running", "0"), ("loaded", "0")]:
                    self.db.set_background_monitor_state(key, value)
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Start at Login Failed", str(exc))
        self.refresh()

    def repair_monitor(self) -> None:
        try:
            stopped = self.service.stop_orphan_processes()
            plist_path, notes = self.launch_agent.repair()
            deadline = time.monotonic() + 10
            detector_updated = False
            baseline = self.db.get_background_monitor_status().detector_last_run_timestamp
            while time.monotonic() < deadline:
                current = self.db.get_background_monitor_status().detector_last_run_timestamp
                if current and current != baseline:
                    detector_updated = True
                    break
                QTimer.singleShot(0, lambda: None)
                time.sleep(1)
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(
                self,
                "Repair Complete",
                "\n".join([f"stopped_orphans={stopped}", *notes, f"detector_timestamp_updated={detector_updated}"]),
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Repair Failed", str(exc))
        self.refresh()

    def force_reinstall_monitor(self) -> None:
        try:
            stopped = self.service.stop_orphan_processes()
            plist_path, notes = self.launch_agent.force_reinstall()
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(
                self,
                "Force Reinstall Complete",
                "\n".join([f"stopped_orphans={stopped}", *notes]),
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Force Reinstall Failed", str(exc))
        self.refresh()

    def restart_monitor(self) -> None:
        try:
            self.launch_agent.stop()
        except Exception:
            pass
        try:
            self.launch_agent.start()
            time.sleep(5)
            self.refresh()
            launch_status = self.launch_agent.status()
            db_status = self.db.get_background_monitor_status()
            process_pid = launch_status.process_pid or db_status.process_pid
            running = is_pid_alive(process_pid) or is_heartbeat_fresh(db_status.last_heartbeat, max_age_seconds=max(120, HEARTBEAT_SECONDS * 2))
            if not running:
                stderr_tail = tail_text_file(self._stderr_log_path(), lines=30) or "none"
                QMessageBox.warning(
                    self,
                    "Restart Failed",
                    f"Monitor did not become healthy after restart.\n\nStderr tail:\n{stderr_tail}",
                )
                return
            QMessageBox.information(self, "Restart Complete", "Background Monitor restarted.")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            stderr_tail = tail_text_file(self._stderr_log_path(), lines=30)
            detail = f"{exc}\n\nStderr tail:\n{stderr_tail}" if stderr_tail else str(exc)
            QMessageBox.warning(self, "Restart Failed", detail)
        self.refresh()

    def start_monitor(self) -> None:
        try:
            self.launch_agent.start()
            self.db.set_background_monitor_state("running", "1")
            self.db.set_background_monitor_state("loaded", "1")
            self.db.set_background_monitor_state("current_launchctl_domain", self.launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Start Failed", str(exc))
        self.refresh()

    def stop_monitor(self) -> None:
        try:
            self.launch_agent.stop()
            self.db.set_background_monitor_state("running", "0")
            self.db.set_background_monitor_state("loaded", "0")
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Stop Failed", str(exc))
        self.refresh()

    def uninstall_monitor(self) -> None:
        try:
            self.launch_agent.stop()
        except Exception:
            pass
        self.launch_agent.uninstall()
        for key, value in [("installed", "0"), ("enabled", "0"), ("running", "0"), ("loaded", "0")]:
            self.db.set_background_monitor_state(key, value)
        self.refresh()

    def run_self_test(self) -> None:
        event = self.service.run_self_test()
        QMessageBox.information(self, "Self-Test Logged", f"Created event: {event.event_type}")
        self.refresh()

    def run_detectors_once(self) -> None:
        events = self.service.run_once()
        QMessageBox.information(self, "Detectors Completed", f"Recorded {len(events)} events to {self.db.path}")
        self.refresh()

    def generate_test_event(self) -> None:
        event = self.service.generate_test_event()
        QMessageBox.information(self, "Test Event Logged", f"Created event: {event.event_type}\nDB: {self.db.path}")
        self.refresh()

    def test_notification(self) -> None:
        result = self.service.test_notification()
        QMessageBox.information(
            self,
            "Test Notification",
            "\n".join(
                [
                    f"success: {'yes' if result.get('success') else 'no'}",
                    f"stderr: {result.get('stderr') or 'none'}",
                    f"osascript exists: {'yes' if result.get('osascript_exists') else 'no'}",
                    f"notification status: {result.get('notification_status') or 'none'}",
                    f"permission note: {result.get('permission_note')}",
                ]
            ),
        )
        self.refresh()

    def test_high_priority_dialog(self) -> None:
        command = ["/usr/bin/python3", str(runtime_monitor_script_path()), "--test-dialog", "--db-path", str(self.db.path)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, cwd=str(Path.cwd()))
            payload = json.loads(result.stdout or "{}")
        except Exception as exc:
            QMessageBox.warning(self, "Test High Priority Dialog Failed", str(exc))
            return
        QMessageBox.information(
            self,
            "Test High Priority Dialog",
            "\n".join(
                [
                    f"success: {'yes' if payload.get('success') else 'no'}",
                    f"stderr: {payload.get('stderr') or 'none'}",
                    f"osascript exists: {'yes' if payload.get('osascript_exists') else 'no'}",
                    f"notification status: {payload.get('notification_status') or 'none'}",
                    f"permission note: {payload.get('permission_note')}",
                ]
            ),
        )
        self.refresh()

    def save_notification_settings(self) -> None:
        try:
            self.notifications.update_settings(
                notify_all_events=self.notify_all_checkbox.isChecked(),
                notify_important_events=self.notify_important_checkbox.isChecked(),
                notify_min_severity=str(self.notify_min_severity_combo.currentData() or "info"),
                notification_sound=self.notification_sound_input.text().strip() or "Glass",
                duplicate_rate_limit_seconds=int(self.rate_limit_input.text().strip() or "10"),
                high_priority_alert_style=str(self.notification_mode_combo.currentData() or "dialog"),
                notification_mode=str(self.notification_mode_combo.currentData() or "dialog"),
                popup_only_severe_events=self.popup_only_severe_checkbox.isChecked(),
                browser_capture_process_popup=self.browser_capture_popup_checkbox.isChecked(),
            )
            self.db.set_background_monitor_state("notification_status", self.notifications.status())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Notification Settings", str(exc))
        self.refresh()

    def _suppressed_popup_count(self) -> int:
        total = 0
        rows = self.db.conn.execute(
            "SELECT value FROM background_monitor_state WHERE key LIKE 'suppressed_notification_count:%'"
        ).fetchall()
        for row in rows:
            try:
                total += int(row["value"] or 0)
            except (TypeError, ValueError):
                continue
        return total

    def _last_notification_decision(self) -> str:
        events = self.db.recent_background_monitor_events(limit=1)
        if not events:
            return "none"
        event = events[0]
        return (
            f"{event.event_type}: {event.notification_decision} "
            f"({event.notification_reason or 'no reason'}) "
            f"popup_allowed={'yes' if event.popup_allowed else 'no'}"
        )

    def show_event_priorities_dialog(self) -> None:
        preferences = self.notifications.event_preferences()
        dialog = QDialog(self)
        dialog.setWindowTitle("Notification Policy")
        layout = QVBoxLayout(dialog)
        table = QTableWidget(len(sorted(preferences)), 6)
        table.setHorizontalHeaderLabels(["Event Type", "Enabled", "Severity", "Popup", "Cooldown", "Alert Style"])
        rows = sorted(preferences.items())
        for row, (event_type, preference) in enumerate(rows):
            table.setItem(row, 0, QTableWidgetItem(event_type))
            enabled = QTableWidgetItem("yes" if preference.get("enabled", True) else "no")
            severity = QTableWidgetItem(str(preference.get("severity", "low")))
            notify = QTableWidgetItem("yes" if preference.get("notify", False) else "no")
            cooldown = QTableWidgetItem(str(preference.get("cooldown_seconds", 0)))
            alert_style = QTableWidgetItem(str(preference.get("notification_mode", "none")))
            table.setItem(row, 1, enabled)
            table.setItem(row, 2, severity)
            table.setItem(row, 3, notify)
            table.setItem(row, 4, cooldown)
            table.setItem(row, 5, alert_style)
        table.resizeColumnsToContents()
        layout.addWidget(table)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        updated: dict[str, dict[str, object]] = {}
        for row in range(table.rowCount()):
            event_type_item = table.item(row, 0)
            if event_type_item is None:
                continue
            event_type = event_type_item.text().strip()
            existing = preferences.get(event_type, {})
            updated[event_type] = {
                "enabled": (table.item(row, 1).text().strip().lower() if table.item(row, 1) else "yes") in {"1", "true", "yes", "on"},
                "severity": table.item(row, 2).text().strip().lower() if table.item(row, 2) else "low",
                "notify": (table.item(row, 3).text().strip().lower() if table.item(row, 3) else "no") in {"1", "true", "yes", "on"},
                "cooldown_seconds": int((table.item(row, 4).text().strip() if table.item(row, 4) else "0") or "0"),
                "notification_mode": table.item(row, 5).text().strip().lower() if table.item(row, 5) else str(existing.get("notification_mode", existing.get("alert_style", "none"))),
            }
        self.notifications.update_event_preferences(updated)
        self.refresh()

    def _simulate(self, event_type: str, evidence: str, *, severity: str = "info", confidence: str = "high", process_name: str = "", pid: int | None = None) -> None:
        event = self.service.simulate_event(
            event_type,
            evidence,
            severity=severity,
            confidence=confidence,
            process_name=process_name,
            pid=pid,
        )
        QMessageBox.information(self, "Simulated Event Logged", f"Created event: {event.event_type}")
        self.refresh()

    def show_logs(self) -> None:
        path = (
            f"LaunchAgent stdout log: {self.launch_agent.show_logs()}\n"
            f"LaunchAgent stderr log: {self._stderr_log_path()}\n"
            f"Fallback monitor log: {self._fallback_log_path_text()}"
        )
        QMessageBox.information(self, "Monitor Logs", path)

    def test_silent_log_event(self) -> None:
        event = self.service.simulate_event(
            "heartbeat",
            "User triggered a silent log event test.",
            severity="info",
            confidence="high",
        )
        QMessageBox.information(self, "Silent Log Event", f"Logged event: {event.event_type}")
        self.refresh()

    def clear_monitor_logs(self) -> None:
        selection = self._prompt_clear_monitor_logs()
        if not selection:
            return
        clear_db = selection["clear_event_history"]
        try:
            self._write_app_log(f"user triggered monitor log clear | clear_event_history={clear_db}")
            clear_monitor_log_files()
            removed = 0
            if clear_db:
                removed = self.db.clear_monitor_events()
            self.service._write_log_line("Monitor logs cleared by user.")
            self._write_app_log("Monitor logs cleared by user.")
            if clear_db:
                self.service._write_log_line("Monitor event history cleared by user.")
                self._write_app_log("Monitor event history cleared by user.")
            self._write_app_log(f"monitor log clear completed | clear_event_history={clear_db} | removed_events={removed}")
            QMessageBox.information(
                self,
                "Monitor Logs Cleared",
                f"Cleared monitor file logs.{f' Removed {removed} monitor events.' if clear_db else ''}",
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            self._write_app_log(f"monitor log clear failed | clear_event_history={clear_db} | error={exc}")
            QMessageBox.warning(self, "Clear Monitor Logs Failed", str(exc))
        self.refresh()

    def _prompt_clear_monitor_logs(self) -> dict[str, bool] | None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Clear Monitor Logs")
        layout = QVBoxLayout(dialog)
        message = QLabel(
            "This will remove monitor log files. This action cannot be undone. "
            "Consider exporting logs first if you need them for investigation."
        )
        message.setWordWrap(True)
        layout.addWidget(message)
        clear_db_checkbox = QCheckBox("Clear file logs + monitor event history (dangerous)")
        layout.addWidget(clear_db_checkbox)
        warning = QLabel("This will also delete recorded monitor events used for historical analysis.")
        warning.setWordWrap(True)
        warning.hide()
        layout.addWidget(warning)
        understand_checkbox = QCheckBox("I understand")
        layout.addWidget(understand_checkbox)
        typed_input = QLineEdit()
        typed_input.setPlaceholderText("Type CLEAR to confirm event history deletion")
        typed_input.hide()
        layout.addWidget(typed_input)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        layout.addWidget(buttons)

        def _sync_state() -> None:
            dangerous = clear_db_checkbox.isChecked()
            warning.setVisible(dangerous)
            typed_input.setVisible(dangerous)

        clear_db_checkbox.toggled.connect(_sync_state)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        _sync_state()
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        if not understand_checkbox.isChecked():
            QMessageBox.warning(self, "Clear Monitor Logs", "Confirmation required: check 'I understand'.")
            return None
        if clear_db_checkbox.isChecked() and typed_input.text().strip() != "CLEAR":
            QMessageBox.warning(self, "Clear Monitor Logs", "Typed confirmation required: enter CLEAR.")
            return None
        return {"clear_event_history": clear_db_checkbox.isChecked()}

    def _monitor_log_paths(self) -> list[Path]:
        default_paths = default_launch_agent_paths()
        stdout_path = Path(self.launch_agent.show_logs()).expanduser()
        stderr_path = getattr(getattr(self.launch_agent, "paths", None), "stderr_path", default_paths.stderr_path)
        return [FALLBACK_MONITOR_LOG.expanduser(), stdout_path, Path(stderr_path).expanduser()]

    def _write_app_log(self, message: str) -> None:
        path = self.db.logs_dir / "app.log"
        try:
            append_monitor_log_line(path, f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}\n")
        except OSError:
            LOGGER.exception("Failed to append app log line: %s", path)

    def show_detector_snapshot(self) -> None:
        snapshot = self.service.collect_detector_snapshot()
        QMessageBox.information(
            self,
            "Detector Snapshot",
            "\n".join(
                [
                    f"Current capture-capable processes: {snapshot.get('capture_capable_processes', [])}",
                    f"Current display state: {snapshot.get('display_state', 'unknown')}",
                    f"Current clamshell state: {snapshot.get('clamshell_state', 'unknown')}",
                    f"Last detector run: {self.db.get_background_monitor_status().detector_last_run_timestamp or 'none'}",
                    f"Events emitted in last detector run: {self.db.get_background_monitor_state('detector_last_emitted_events', '0')}",
                ]
            ),
        )
        self.refresh()

    def export_json(self) -> None:
        default_path = get_reports_dir() / "background_monitor.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export Monitor JSON", str(default_path), "JSON Files (*.json)")
        if not path:
            return
        events = [item.to_dict() for item in self.db.recent_background_monitor_events(limit=5000, event_type=str(self.filter_combo.currentData() or "") or None)]
        try:
            saved_path = export_monitor_events_json(events, Path(path))
        except OSError as exc:
            LOGGER.exception("Failed to export monitor JSON to %s", path)
            QMessageBox.critical(self, "Export Failed", f"Failed to export monitor JSON:\n{path}\n\n{exc}")
            return
        QMessageBox.information(self, "Monitor JSON Exported", f"Saved monitor JSON to:\n{saved_path}")

    def export_html(self) -> None:
        default_path = get_reports_dir() / "background_monitor.html"
        path, _ = QFileDialog.getSaveFileName(self, "Export Monitor HTML", str(default_path), "HTML Files (*.html)")
        if not path:
            return
        events = [item.to_dict() for item in self.db.recent_background_monitor_events(limit=5000, event_type=str(self.filter_combo.currentData() or "") or None)]
        try:
            saved_path = export_monitor_events_html(events, Path(path))
        except OSError as exc:
            LOGGER.exception("Failed to export monitor HTML to %s", path)
            QMessageBox.critical(self, "Export Failed", f"Failed to export monitor HTML:\n{path}\n\n{exc}")
            return
        QMessageBox.information(self, "Monitor HTML Exported", f"Saved monitor HTML to:\n{saved_path}")
