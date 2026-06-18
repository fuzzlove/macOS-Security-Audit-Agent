from __future__ import annotations

import json
import logging
import os
import subprocess
import stat
from pathlib import Path
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
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

from mac_audit_agent.emergency_lockdown import (
    CONFIRMATION_TEXT,
    LAST_ACTION_STATE_KEY,
    LAST_FAILURE_STATE_KEY,
    LAST_TRACE_STATE_KEY,
    POLICY_ASSIST_USER,
    POLICY_ATTEMPT_ACTIVATION,
    POLICY_DISABLED,
    POLICY_MANAGED_ENVIRONMENT,
    POLICY_RECOMMEND_ONLY,
    enable_lockdown_with_user_policy,
    get_lockdown_status,
    load_policy,
    open_lockdown_settings_fallback,
    run_lockdown_test_workflow,
    save_policy,
)
from mac_audit_agent.launch_agent import (
    LaunchAgentManager,
    LAUNCHCTL_BIN,
    MONITOR_ROLE_SYSTEM,
    MONITOR_ROLE_USER,
    default_launch_agent_paths,
    default_monitor_db_path,
    protected_monitor_manifest_path,
    runtime_monitor_script_path,
    runtime_root,
    verify_protected_monitor_integrity,
)
from mac_audit_agent.monitor import (
    DISCLAIMER,
    FALLBACK_MONITOR_LOG,
    BackgroundMonitorService,
    HEARTBEAT_SECONDS,
    STDERR_MONITOR_LOG,
    append_monitor_log_line,
    is_heartbeat_fresh,
    is_pid_alive,
    tail_text_file,
    truncate_monitor_log_file,
)
from mac_audit_agent.ui.action_state import ActionState, apply_action_state
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.reporting import export_monitor_events_html, export_monitor_events_json, get_reports_dir
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness
from mac_audit_agent.ui.context_dialog import ContextDialog
from mac_audit_agent.ui.provenance_dialog import AlertProvenanceDialog
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer

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
    "launchdaemon_added",
    "launchagent_added",
    "persistence_item_created_high_risk",
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
    "usb_device_connected",
    "system_moisture_detected",
    "network_ip_assigned",
    "vpn_connected",
    "major_security_event",
    "monitor_self_test",
    "monitor_test_event",
    "protected_monitor_tamper_detected",
]


class MonitorProtectionDialog(QDialog):
    def __init__(self, panel: "BackgroundMonitorPanel", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.panel = panel
        self.setWindowTitle("Monitor Protection")
        layout = QVBoxLayout(self)
        warning = QLabel(
            "Protected Mode installs the monitor as a root-owned LaunchDaemon. Standard users and non-admin malware should not be able to modify or remove it. Administrators can still uninstall it. This is not stealth protection and does not guarantee malware resistance."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.mode_label = QLabel("")
        self.installed_path_label = QLabel("")
        self.service_loaded_label = QLabel("")
        self.owner_mode_label = QLabel("")
        self.integrity_label = QLabel("")
        self.last_tamper_label = QLabel("")
        for label in [
            self.mode_label,
            self.installed_path_label,
            self.service_loaded_label,
            self.owner_mode_label,
            self.integrity_label,
            self.last_tamper_label,
        ]:
            label.setWordWrap(True)
            layout.addWidget(label)
        self.remove_runtime_checkbox = QCheckBox("Remove runtime files when uninstalling protected mode")
        layout.addWidget(self.remove_runtime_checkbox)
        row = QHBoxLayout()
        self.install_button = QPushButton("Install Protected Mode")
        self.verify_button = QPushButton("Verify Protection")
        self.lockdown_button = QPushButton("Lock Down Protected Files")
        self.repair_button = QPushButton("Repair Protected Mode")
        self.uninstall_button = QPushButton("Uninstall Protected Mode")
        self.revert_button = QPushButton("Revert to User Mode")
        for button in [self.install_button, self.verify_button, self.lockdown_button, self.repair_button, self.uninstall_button, self.revert_button]:
            row.addWidget(button)
        layout.addLayout(row)
        self.install_button.clicked.connect(self.panel.install_protected_mode)
        self.verify_button.clicked.connect(self.panel.verify_monitor_protection)
        self.lockdown_button.clicked.connect(self.panel.lock_down_protected_files)
        self.repair_button.clicked.connect(self.panel.repair_protected_mode)
        self.uninstall_button.clicked.connect(self.panel.uninstall_protected_mode)
        self.revert_button.clicked.connect(self.panel.revert_to_user_mode)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Close)
        self.button_box.rejected.connect(self.reject)
        self.button_box.accepted.connect(self.accept)
        layout.addWidget(self.button_box)

    def refresh_state(self, state: dict[str, object]) -> None:
        self.mode_label.setText(f"Current mode: {state.get('mode_label', 'User Mode')}")
        self.installed_path_label.setText(f"Installed path: {state.get('plist_path', '')}")
        self.service_loaded_label.setText(f"Service loaded: {'yes' if state.get('loaded') else 'no'} | Running: {'yes' if state.get('running') else 'no'}")
        self.owner_mode_label.setText(f"Owner/mode status: {state.get('owner_mode_status', 'unknown')}")
        self.integrity_label.setText(f"Runtime integrity status: {state.get('integrity_status', 'unknown')}")
        self.last_tamper_label.setText(f"Last tamper check: {state.get('last_tamper_check', 'not yet')}")


class MonitorModeDialog(QDialog):
    def __init__(self, panel: "BackgroundMonitorPanel", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.panel = panel
        self.setWindowTitle("Monitor Mode")
        layout = QVBoxLayout(self)
        warning = QLabel(
            "System Monitor Mode installs a root-owned LaunchDaemon that starts at boot. It can collect system-level events before user login, but it cannot directly show GUI alerts. User notifications require the User Notifier helper after login. Administrators can uninstall it."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.mode_label = QLabel("")
        self.system_status_label = QLabel("")
        self.user_status_label = QLabel("")
        self.system_path_label = QLabel("")
        self.user_path_label = QLabel("")
        self.integrity_label = QLabel("")
        for label in [
            self.mode_label,
            self.system_status_label,
            self.user_status_label,
            self.system_path_label,
            self.user_path_label,
            self.integrity_label,
        ]:
            label.setWordWrap(True)
            layout.addWidget(label)
        row = QHBoxLayout()
        self.install_system_button = QPushButton("Install System Monitor")
        self.start_system_button = QPushButton("Start System Monitor")
        self.stop_system_button = QPushButton("Stop System Monitor")
        self.restart_system_button = QPushButton("Restart System Monitor")
        self.repair_system_button = QPushButton("Repair System Monitor")
        self.uninstall_system_button = QPushButton("Uninstall System Monitor")
        self.install_user_button = QPushButton("Install User Notifier")
        self.test_flow_button = QPushButton("Test Event Flow")
        for button in [
            self.install_system_button,
            self.start_system_button,
            self.stop_system_button,
            self.restart_system_button,
            self.repair_system_button,
            self.uninstall_system_button,
            self.install_user_button,
            self.test_flow_button,
        ]:
            row.addWidget(button)
        layout.addLayout(row)
        self.install_system_button.clicked.connect(self.panel.install_system_monitor)
        self.start_system_button.clicked.connect(self.panel.start_system_monitor)
        self.stop_system_button.clicked.connect(self.panel.stop_system_monitor)
        self.restart_system_button.clicked.connect(self.panel.restart_system_monitor)
        self.repair_system_button.clicked.connect(self.panel.repair_system_monitor)
        self.uninstall_system_button.clicked.connect(self.panel.uninstall_system_monitor)
        self.install_user_button.clicked.connect(self.panel.install_user_notifier)
        self.test_flow_button.clicked.connect(self.panel.test_event_flow)
        self.button_box = QDialogButtonBox(QDialogButtonBox.Close)
        self.button_box.rejected.connect(self.reject)
        self.button_box.accepted.connect(self.accept)
        layout.addWidget(self.button_box)

    def refresh_state(self, state: dict[str, object]) -> None:
        self.mode_label.setText(f"Current mode: {state.get('current_mode', 'User Monitor Mode')}")
        self.system_status_label.setText(f"System monitor: {state.get('system_status', 'unknown')}")
        self.user_status_label.setText(f"User notifier: {state.get('user_status', 'unknown')}")
        self.system_path_label.setText(f"System plist: {state.get('system_plist_path', '')}")
        self.user_path_label.setText(f"User plist: {state.get('user_plist_path', '')}")
        self.integrity_label.setText(f"Integrity: {state.get('integrity_status', 'unknown')}")


class BackgroundMonitorPanel(QWidget):
    def __init__(self, db: AuditDatabase, launch_agent: LaunchAgentManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self.launch_agent = launch_agent
        self.system_launch_agent = LaunchAgentManager(default_monitor_db_path("system"), scope="system")
        self.protected_launch_agent = self.system_launch_agent
        self.service = BackgroundMonitorService(self.db.path, record_startup=False)
        self.notifications = NotificationManager(self.db)
        self.workflow_layer = InvestigatorWorkflowLayer(self.db)
        self.system_readiness = SystemMonitorReadiness(default_monitor_db_path("system"))
        self._notification_service_cache: BackgroundMonitorService | None = None
        self._notification_service_db_path = ""
        self._event_service_cache: BackgroundMonitorService | None = None
        self._event_service_db_path = ""
        self.current_events: list = []
        self._build_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(5000)
        self.refresh()

    def _fallback_log_path_text(self) -> str:
        return str(FALLBACK_MONITOR_LOG.expanduser().resolve())

    def _system_user_notifier_manager(self) -> LaunchAgentManager:
        return LaunchAgentManager(default_monitor_db_path("system"), scope="user")

    def _active_monitor_db(self) -> AuditDatabase:
        system_db_path = default_monitor_db_path("system")
        if self._system_mode_enabled():
            try:
                if self.db.path == system_db_path:
                    return self.db
                return AuditDatabase(system_db_path)
            except Exception as exc:
                self.db.set_background_monitor_state("last_error", f"Unable to open shared system monitor database: {exc}")
                return self.db
        return self.db

    def _notification_service(self) -> BackgroundMonitorService:
        active_db = self._active_monitor_db()
        db_path = str(active_db.path)
        if self._notification_service_cache is None or self._notification_service_db_path != db_path:
            self._notification_service_cache = BackgroundMonitorService(active_db.path, record_startup=False, mode=MONITOR_ROLE_USER)
            self._notification_service_db_path = db_path
        return self._notification_service_cache

    def _event_service(self) -> BackgroundMonitorService:
        if not self._system_mode_enabled():
            return self.service
        active_db = self._active_monitor_db()
        db_path = str(active_db.path)
        if self._event_service_cache is None or self._event_service_db_path != db_path:
            self._event_service_cache = BackgroundMonitorService(active_db.path, record_startup=False, mode=MONITOR_ROLE_SYSTEM)
            self._event_service_db_path = db_path
        return self._event_service_cache

    def _notifier_manager(self) -> LaunchAgentManager:
        return self._system_user_notifier_manager() if self._system_mode_enabled() else self.launch_agent

    def _repair_alerts_log_tail(self) -> str:
        tails = [
            tail_text_file(self._stderr_log_path(), lines=30),
            tail_text_file(FALLBACK_MONITOR_LOG.expanduser(), lines=30),
        ]
        tail = "\n".join(part for part in tails if part)
        return tail or "none"

    def _system_mode_enabled(self) -> bool:
        return self.db.get_background_monitor_state("monitor_mode", "user") in {"protected", "system"}

    def _detector_manager(self) -> LaunchAgentManager:
        return self.system_launch_agent if self._system_mode_enabled() else self.launch_agent

    def _stderr_log_path(self) -> Path:
        stderr_path = getattr(getattr(self._detector_manager(), "paths", None), "stderr_path", STDERR_MONITOR_LOG)
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
        self.developer_mode_enabled = False
        self.status_label = QLabel("Status: unknown")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        disclaimer = QLabel(DISCLAIMER)
        disclaimer.setWordWrap(True)
        layout.addWidget(disclaimer)

        controls = QHBoxLayout()
        self.install_button = QPushButton("Install System Monitor + User Notifier")
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
        self.test_bottom_right_alert_button = QPushButton("Test Bottom-Right Alert")
        self.test_critical_alert_button = QPushButton("Test Critical Alert")
        self.test_idle_warning_button = QPushButton("Test Idle Activity Warning")
        self.repair_alerts_button = QPushButton("Repair Alerts / Notifier")
        self.event_priorities_button = QPushButton("Event Priorities")
        self.audit_deployment_button = QPushButton("Audit System Monitor Deployment")
        self.verify_event_flow_button = QPushButton("Verify Event Flow")
        self.repair_deployment_button = QPushButton("Repair System Monitor Deployment")
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
            self.test_bottom_right_alert_button,
            self.test_critical_alert_button,
            self.test_idle_warning_button,
            self.repair_alerts_button,
            self.event_priorities_button,
            self.audit_deployment_button,
            self.verify_event_flow_button,
            self.repair_deployment_button,
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
        settings_layout.addWidget(QLabel("Show Bottom-Right Alerts"), 2, 0)
        self.show_visible_alerts_checkbox = QCheckBox()
        self.show_visible_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_visible_alerts_checkbox, 2, 1)
        settings_layout.addWidget(QLabel("Physical/Session"), 2, 2)
        self.show_physical_session_alerts_checkbox = QCheckBox()
        self.show_physical_session_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_physical_session_alerts_checkbox, 2, 3)
        settings_layout.addWidget(QLabel("USB/Bluetooth"), 2, 4)
        self.show_usb_bluetooth_alerts_checkbox = QCheckBox()
        self.show_usb_bluetooth_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_usb_bluetooth_alerts_checkbox, 2, 5)
        settings_layout.addWidget(QLabel("Network"), 2, 6)
        self.show_network_change_alerts_checkbox = QCheckBox()
        self.show_network_change_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_network_change_alerts_checkbox, 2, 7)
        settings_layout.addWidget(QLabel("Admin/Persistence"), 2, 8)
        self.show_admin_persistence_alerts_checkbox = QCheckBox()
        self.show_admin_persistence_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_admin_persistence_alerts_checkbox, 2, 9)
        settings_layout.addWidget(QLabel("Apple Forecast"), 2, 10)
        self.show_apple_forecast_alerts_checkbox = QCheckBox()
        self.show_apple_forecast_alerts_checkbox.setChecked(True)
        settings_layout.addWidget(self.show_apple_forecast_alerts_checkbox, 2, 11)
        settings_layout.addWidget(QLabel("Idle Warning Minutes"), 2, 12)
        self.idle_warning_minutes_input = QLineEdit("2")
        settings_layout.addWidget(self.idle_warning_minutes_input, 2, 13)
        settings_layout.addWidget(QLabel("CFAA Idle Warning"), 2, 14)
        self.cfaa_idle_warning_checkbox = QCheckBox()
        self.cfaa_idle_warning_checkbox.setChecked(True)
        settings_layout.addWidget(self.cfaa_idle_warning_checkbox, 2, 15)
        settings_layout.addWidget(QLabel("Category Cooldown Seconds"), 3, 0)
        self.cooldown_seconds_input = QLineEdit("600")
        settings_layout.addWidget(self.cooldown_seconds_input, 3, 1)
        layout.addLayout(settings_layout)

        emergency_layout = QGridLayout()
        emergency_title = QLabel("Security Response > Emergency Lockdown")
        emergency_title.setStyleSheet("font-weight: 700;")
        emergency_layout.addWidget(emergency_title, 0, 0, 1, 4)
        self.lockdown_status_label = QLabel("Current Lockdown Mode status: unknown")
        self.lockdown_policy_label = QLabel("Response policy: Recommend Only")
        self.lockdown_last_action_label = QLabel("Last emergency lockdown action: none")
        self.lockdown_last_failure_label = QLabel("Last failure: none")
        self.lockdown_diagnostics_label = QLabel("Lockdown Diagnostics: no activation trace recorded")
        for row, label in enumerate(
            [
                self.lockdown_status_label,
                self.lockdown_policy_label,
                self.lockdown_last_action_label,
                self.lockdown_last_failure_label,
                self.lockdown_diagnostics_label,
            ],
            start=1,
        ):
            label.setWordWrap(True)
            emergency_layout.addWidget(label, row, 0, 1, 4)
        warning = QLabel(
            "Emergency Lockdown may interrupt apps, websites, messages, attachments, device connections, and workflows. Automatic activation is only allowed when a supported macOS method is verified; otherwise Mac Audit Agent opens guidance and records the failure reason."
        )
        warning.setWordWrap(True)
        emergency_layout.addWidget(warning, 6, 0, 1, 4)
        emergency_layout.addWidget(QLabel("Policy"), 7, 0)
        self.lockdown_policy_combo = QComboBox()
        self.lockdown_policy_combo.addItem("Disabled", POLICY_DISABLED)
        self.lockdown_policy_combo.addItem("Recommend Only", POLICY_RECOMMEND_ONLY)
        self.lockdown_policy_combo.addItem("Assist User", POLICY_ASSIST_USER)
        self.lockdown_policy_combo.addItem("Attempt Activation", POLICY_ATTEMPT_ACTIVATION)
        self.lockdown_policy_combo.addItem("Managed Environment", POLICY_MANAGED_ENVIRONMENT)
        emergency_layout.addWidget(self.lockdown_policy_combo, 7, 1)
        self.lockdown_understand_checkbox = QCheckBox("I understand")
        emergency_layout.addWidget(self.lockdown_understand_checkbox, 7, 2)
        self.lockdown_require_admin_checkbox = QCheckBox("Require admin approval if needed")
        self.lockdown_require_admin_checkbox.setChecked(True)
        emergency_layout.addWidget(self.lockdown_require_admin_checkbox, 7, 3)
        emergency_layout.addWidget(QLabel("Typed confirmation"), 8, 0)
        self.lockdown_confirmation_input = QLineEdit()
        self.lockdown_confirmation_input.setPlaceholderText(CONFIRMATION_TEXT)
        emergency_layout.addWidget(self.lockdown_confirmation_input, 8, 1, 1, 2)
        self.save_lockdown_policy_button = QPushButton("Save Emergency Lockdown Policy")
        self.lockdown_test_center_title = QLabel("Test Lockdown Workflow")
        self.lockdown_test_center_title.setStyleSheet("font-weight: 700;")
        self.lockdown_dry_run_button = QPushButton("Dry Run Critical Event")
        self.lockdown_assist_test_button = QPushButton("Simulate Critical Event - Assist Mode")
        self.lockdown_attempt_test_button = QPushButton("Simulate Critical Event - Attempt Activation")
        self.view_lockdown_trace_button = QPushButton("View Last Lockdown Trace")
        self.copy_lockdown_diagnostics_button = QPushButton("Copy Lockdown Diagnostics")
        self.lockdown_dry_run_button.setToolTip("Dry-run only: shows what the policy would do for a critical event without changing Lockdown Mode.")
        self.lockdown_assist_test_button.setToolTip("Creates evidence, opens Lockdown Mode settings, and shows the required user-action alert.")
        self.lockdown_attempt_test_button.setToolTip("Attempts automatic activation only if supported; otherwise falls back to assisted activation.")
        self.view_lockdown_trace_button.setToolTip("Show the full last LockdownActivationTrace JSON.")
        self.copy_lockdown_diagnostics_button.setToolTip("Copy the latest Lockdown activation trace and failure classification.")
        emergency_layout.addWidget(self.save_lockdown_policy_button, 8, 3)
        emergency_layout.addWidget(self.lockdown_test_center_title, 9, 0, 1, 4)
        emergency_layout.addWidget(self.lockdown_dry_run_button, 10, 0)
        emergency_layout.addWidget(self.lockdown_assist_test_button, 10, 1)
        emergency_layout.addWidget(self.lockdown_attempt_test_button, 10, 2)
        emergency_layout.addWidget(self.view_lockdown_trace_button, 10, 3)
        emergency_layout.addWidget(self.copy_lockdown_diagnostics_button, 11, 3)
        layout.addLayout(emergency_layout)

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

        self.events_table = QTableWidget(0, 8)
        self.events_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Severity", "Source", "Process", "Confidence", "Occurrences", "Evidence"])
        self.events_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.events_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.events_table.itemSelectionChanged.connect(self._update_selected_event_context_state)
        self.events_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.events_table)
        event_context_row = QHBoxLayout()
        self.show_context_button = QPushButton("Show Context")
        self.show_context_button.setEnabled(False)
        self.show_context_button.clicked.connect(self.show_selected_event_context)
        self.show_provenance_button = QPushButton("Why did this alert fire?")
        self.show_provenance_button.setEnabled(False)
        self.show_provenance_button.clicked.connect(self.show_selected_event_provenance)
        self.show_alert_trace_button = QPushButton("Alert Pipeline Trace")
        self.show_alert_trace_button.setEnabled(False)
        self.show_alert_trace_button.clicked.connect(self.show_selected_alert_pipeline_trace)
        event_context_row.addWidget(self.show_context_button)
        event_context_row.addWidget(self.show_provenance_button)
        event_context_row.addWidget(self.show_alert_trace_button)
        event_context_row.addStretch(1)
        layout.addLayout(event_context_row)

        layout.addWidget(QLabel("Show Monitor Health"))
        self.health_panel = QTextEdit()
        self.health_panel.setReadOnly(True)
        layout.addWidget(self.health_panel)

        layout.addWidget(QLabel("System Monitor Operational Readiness"))
        self.deployment_audit_panel = QTextEdit()
        self.deployment_audit_panel.setReadOnly(True)
        self.deployment_audit_panel.setPlainText("Click Audit System Monitor Deployment to verify launchd, runtime, shared DB, heartbeat, version, permissions, and event flow readiness.")
        layout.addWidget(self.deployment_audit_panel)

        layout.addWidget(QLabel("What am I looking at?"))
        self.explanation = QTextEdit()
        self.explanation.setReadOnly(True)
        self.explanation.setPlainText(
            "This panel shows local privacy indicators and session state transitions recorded by the optional root-owned system LaunchDaemon. "
            "A user-session LaunchAgent companion can display notifications after login, but it does not run the detector loop. "
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
        self.test_bottom_right_alert_button.clicked.connect(self.test_bottom_right_alert)
        self.test_critical_alert_button.clicked.connect(self.test_critical_alert)
        self.test_idle_warning_button.clicked.connect(self.test_idle_activity_warning)
        self.repair_alerts_button.clicked.connect(self.repair_alerts_notifier)
        self.event_priorities_button.clicked.connect(self.show_event_priorities_dialog)
        self.audit_deployment_button.clicked.connect(self.audit_system_monitor_deployment)
        self.verify_event_flow_button.clicked.connect(self.verify_system_monitor_event_flow)
        self.repair_deployment_button.clicked.connect(self.repair_system_monitor_deployment)
        self.save_settings_button.clicked.connect(self.save_notification_settings)
        self.save_lockdown_policy_button.clicked.connect(self.save_emergency_lockdown_policy)
        self.lockdown_dry_run_button.clicked.connect(self.dry_run_emergency_lockdown_policy)
        self.lockdown_assist_test_button.clicked.connect(self.simulate_lockdown_assist_mode)
        self.lockdown_attempt_test_button.clicked.connect(self.simulate_lockdown_attempt_activation)
        self.view_lockdown_trace_button.clicked.connect(self.view_last_lockdown_trace)
        self.copy_lockdown_diagnostics_button.clicked.connect(self.copy_lockdown_diagnostics)
        self.continuous_monitoring_checkbox.toggled.connect(self.toggle_continuous_monitoring)
        self.start_at_login_checkbox.toggled.connect(self.toggle_start_at_login)
        self.filter_combo.currentIndexChanged.connect(self.refresh_events)
        self.export_json_button.clicked.connect(self.export_json)
        self.export_html_button.clicked.connect(self.export_html)
        self.set_developer_mode(False)
        self.refresh_emergency_lockdown_policy()

    def developer_only_buttons(self) -> list[QWidget]:
        return [
            self.test_notification_button,
            self.test_dialog_button,
            self.test_silent_event_button,
            self.test_event_button,
            self.test_bottom_right_alert_button,
            self.test_critical_alert_button,
            self.test_idle_warning_button,
            self.verify_event_flow_button,
            self.lockdown_test_center_title,
            self.lockdown_dry_run_button,
            self.lockdown_assist_test_button,
            self.lockdown_attempt_test_button,
        ]

    def set_developer_mode(self, enabled: bool) -> None:
        self.developer_mode_enabled = enabled
        for button in self.developer_only_buttons():
            button.setVisible(enabled)
            button.setToolTip(
                "Developer Mode only: generates synthetic monitor/notifier events and never belongs in the normal production workflow."
                if enabled
                else "Hidden unless Settings > Developer Mode is enabled."
            )

    def refresh_emergency_lockdown_policy(self) -> None:
        policy = load_policy(self.db)
        mode = str(policy.get("mode", POLICY_RECOMMEND_ONLY))
        index = self.lockdown_policy_combo.findData(mode)
        self.lockdown_policy_combo.setCurrentIndex(index if index >= 0 else 0)
        self.lockdown_understand_checkbox.setChecked(bool(policy.get("understood", False)))
        self.lockdown_require_admin_checkbox.setChecked(bool(policy.get("require_admin_approval", True)))
        self.lockdown_confirmation_input.setText(str(policy.get("confirmation", "")))
        self.lockdown_policy_label.setText(f"Response policy: {self.lockdown_policy_combo.currentText()}")
        status = get_lockdown_status()
        self.lockdown_status_label.setText(f"Current Lockdown Mode status: {status.get('status', 'unknown')} ({status.get('evidence', '')})")
        raw_last = self.db.get_background_monitor_state(LAST_ACTION_STATE_KEY, "")
        if raw_last:
            try:
                last = json.loads(raw_last)
            except json.JSONDecodeError:
                last = {}
            self.lockdown_last_action_label.setText(
                f"Last emergency lockdown action: {last.get('timestamp', '')} | attempted={last.get('action_attempted', '')} | success={last.get('action_success', False)}"
            )
        else:
            self.lockdown_last_action_label.setText("Last emergency lockdown action: none")
        self.lockdown_last_failure_label.setText(f"Last failure: {self.db.get_background_monitor_state(LAST_FAILURE_STATE_KEY, 'none') or 'none'}")
        trace = self._latest_lockdown_trace()
        if trace:
            self.lockdown_diagnostics_label.setText(
                "Lockdown Diagnostics: "
                f"policy={trace.get('policy_mode', '')} | "
                f"configured_policy={trace.get('configured_policy_mode', trace.get('policy_mode', ''))} | "
                f"dry_run={trace.get('dry_run', False)} | "
                f"method={trace.get('activation_method', trace.get('enable_method', ''))} | "
                f"auto_supported={trace.get('automatic_activation_supported', trace.get('activation_supported', False))} | "
                f"assist_supported={trace.get('assisted_activation_supported', False)} | "
                f"requires_user_action={trace.get('requires_user_action', False)} | "
                f"settings_opened={trace.get('settings_opened', False)} | "
                f"verification={trace.get('verification_method', 'unknown')} | "
                f"status={trace.get('lockdown_status_before', 'unknown')}->{trace.get('lockdown_status_after', 'unknown')} | "
                f"confidence={trace.get('status_confidence', 'unknown')} | "
                f"result={trace.get('verification_result', trace.get('lockdown_status_after', 'unknown'))} | "
                f"failure={trace.get('failure_reason', '')}"
            )
        else:
            self.lockdown_diagnostics_label.setText("Lockdown Diagnostics: no activation trace recorded")

    def _latest_lockdown_trace(self) -> dict:
        raw = self.db.get_background_monitor_state(LAST_TRACE_STATE_KEY, "")
        if not raw:
            return {}
        try:
            trace = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return trace if isinstance(trace, dict) else {}

    def copy_lockdown_diagnostics(self) -> None:
        status = get_lockdown_status()
        trace = self._latest_lockdown_trace()
        action_raw = self.db.get_background_monitor_state(LAST_ACTION_STATE_KEY, "")
        failure = self.db.get_background_monitor_state(LAST_FAILURE_STATE_KEY, "")
        diagnostics = {
            "policy_mode": trace.get("policy_mode", ""),
            "configured_policy_mode": trace.get("configured_policy_mode", trace.get("policy_mode", "")),
            "dry_run": trace.get("dry_run", False),
            "current_status": status.get("status", "unknown"),
            "current_status_evidence": status.get("evidence", ""),
            "current_status_confidence": status.get("confidence", "unknown"),
            "last_attempt": action_raw,
            "last_trigger": trace.get("trigger_event", ""),
            "last_trigger_id": trace.get("trigger_event_id", trace.get("trigger_event", "")),
            "snapshot_created": trace.get("snapshot_created", False),
            "snapshot_path": trace.get("snapshot_path", ""),
            "activation_method": trace.get("activation_method", trace.get("enable_method", "")),
            "activation_path": trace.get("activation_path", ""),
            "automatic_activation_supported": trace.get("automatic_activation_supported", trace.get("activation_supported", False)),
            "assisted_activation_supported": trace.get("assisted_activation_supported", False),
            "requires_user_action": trace.get("requires_user_action", False),
            "settings_opened": trace.get("settings_opened", False),
            "status_before": trace.get("lockdown_status_before", ""),
            "status_after": trace.get("lockdown_status_after", ""),
            "status_confidence": trace.get("status_confidence", ""),
            "verification_method": trace.get("verification_method", ""),
            "verification_result": trace.get("verification_result", ""),
            "failure_reason": trace.get("failure_reason", failure),
            "full_error": failure,
            "trace": trace,
        }
        QApplication.clipboard().setText(json.dumps(diagnostics, indent=2, sort_keys=True))
        QMessageBox.information(self, "Lockdown Diagnostics", "Lockdown diagnostics copied to the clipboard.")

    def view_last_lockdown_trace(self) -> None:
        trace = self._latest_lockdown_trace()
        if not trace:
            QMessageBox.information(self, "Last Lockdown Trace", "No LockdownActivationTrace has been recorded yet.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Last Lockdown Trace")
        layout = QVBoxLayout(dialog)
        trace_view = QTextEdit()
        trace_view.setReadOnly(True)
        trace_view.setPlainText(json.dumps(trace, indent=2, sort_keys=True))
        layout.addWidget(trace_view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.resize(780, 560)
        dialog.exec()

    def save_emergency_lockdown_policy(self) -> None:
        try:
            policy = save_policy(
                self.db,
                mode=str(self.lockdown_policy_combo.currentData() or POLICY_DISABLED),
                understood=self.lockdown_understand_checkbox.isChecked(),
                confirmation=self.lockdown_confirmation_input.text(),
                require_admin_approval=self.lockdown_require_admin_checkbox.isChecked(),
                create_snapshot_first=True,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Emergency Lockdown Policy", str(exc))
            return
        QMessageBox.information(self, "Emergency Lockdown Policy", f"Policy saved: {policy.get('mode', POLICY_DISABLED)}")
        self.refresh_emergency_lockdown_policy()

    def dry_run_emergency_lockdown_policy(self) -> None:
        action = run_lockdown_test_workflow(
            self.db,
            policy_mode="dry_run_only",
            test_type="dry_run_critical_event",
            config=None,
            notice_callback=lambda _reason: self._show_lockdown_dry_run_notice(),
        )
        QMessageBox.information(
            self,
            "Dry Run Critical Event",
            "\n".join(
                [
                    "Dry run only. No Lockdown Mode setting was changed and System Settings was not opened.",
                    f"Execution mode: {action.policy_mode}",
                    f"Configured policy: {action.configured_policy_mode or action.policy_mode}",
                    f"Snapshot previewed: {'yes' if action.snapshot_created else 'no'}",
                    f"Action path: {action.action_attempted}",
                    f"Result: {'allowed' if action.action_success else 'not attempted'}",
                    f"Reason: {action.error or action.trigger_reason}",
                ]
            ),
        )
        self.refresh_emergency_lockdown_policy()

    def simulate_lockdown_assist_mode(self) -> None:
        action = run_lockdown_test_workflow(
            self.db,
            policy_mode=POLICY_ASSIST_USER,
            test_type="simulate_critical_event_assist_mode",
            config=None,
            notice_callback=lambda _reason: True,
        )
        self._show_emergency_lockdown_action_required(action)
        self._show_lockdown_action_result("Simulate Critical Event - Assist Mode", action)
        self.refresh_emergency_lockdown_policy()

    def simulate_lockdown_attempt_activation(self) -> None:
        action = run_lockdown_test_workflow(
            self.db,
            policy_mode=POLICY_ATTEMPT_ACTIVATION,
            test_type="simulate_critical_event_attempt_activation",
            config=None,
            notice_callback=lambda _reason: True,
        )
        if action.requires_user_action:
            self._show_emergency_lockdown_action_required(action)
        self._show_lockdown_action_result("Simulate Critical Event - Attempt Activation", action)
        self.refresh_emergency_lockdown_policy()

    def _show_lockdown_dry_run_notice(self) -> bool:
        QMessageBox.information(
            self,
            "Dry Run Critical Event",
            "Dry run only. A critical security event was simulated, but no system state was changed and Lockdown Mode settings were not opened.",
        )
        return True

    def _show_emergency_lockdown_action_required(self, action) -> bool:
        message = QMessageBox(self)
        message.setIcon(QMessageBox.Icon.Critical)
        message.setWindowTitle("Emergency Lockdown Action Required")
        message.setText("Emergency Lockdown Action Required")
        message.setInformativeText(
            "A critical security event triggered Emergency Lockdown policy. macOS requires user confirmation to enable Lockdown Mode. "
            "The Lockdown Mode settings panel has been opened. Complete \"Turn On & Restart\" to enable Lockdown Mode."
        )
        open_button = message.addButton("Open Lockdown Settings", QMessageBox.ButtonRole.ActionRole)
        snapshot_button = message.addButton("View Evidence Snapshot", QMessageBox.ButtonRole.ActionRole)
        acknowledge_button = message.addButton("Acknowledge", QMessageBox.ButtonRole.AcceptRole)
        message.exec()
        clicked = message.clickedButton()
        if clicked == open_button:
            open_lockdown_settings_fallback()
        elif clicked == snapshot_button:
            snapshot_path = getattr(action, "snapshot_path", "") or ""
            if snapshot_path:
                QMessageBox.information(self, "Evidence Snapshot", f"Evidence snapshot:\n{snapshot_path}")
            else:
                QMessageBox.information(self, "Evidence Snapshot", "No evidence snapshot path was recorded.")
        return clicked in {open_button, snapshot_button, acknowledge_button}

    def _show_lockdown_action_result(self, title: str, action) -> None:
        status_line = ""
        if action.lockdown_status_after == "unknown":
            status_line = (
                "Lockdown Mode status could not be confirmed automatically. Verify manually in System Settings > Privacy & Security > Lockdown Mode."
            )
        elif action.lockdown_status_after == "enabled":
            status_line = "Lockdown Mode is reported enabled by the current status probe."
        else:
            status_line = f"Lockdown Mode status after action: {action.lockdown_status_after}"
        automatic_line = ""
        if action.action_attempted == "assist_user_fallback":
            automatic_line = "Lockdown Mode cannot be enabled automatically on this Mac through a verified public API. User action is required."
        QMessageBox.information(
            self,
            title,
            "\n".join(
                item
                for item in [
                    automatic_line,
                    f"Policy mode: {action.policy_mode}",
                    f"Action attempted: {action.action_attempted}",
                    f"Settings opened: {'true' if action.settings_opened else 'false'}",
                    f"Requires user action: {'true' if action.requires_user_action else 'false'}",
                    f"Snapshot created: {'true' if action.snapshot_created else 'false'}",
                    f"Snapshot path: {action.snapshot_path or '(none)'}",
                    f"Success: {'true' if action.action_success else 'false'}",
                    f"Failure reason: {action.error or '(none)'}",
                    status_line,
                ]
                if item
            ),
        )

    def _monitor_protection_state(self) -> dict[str, object]:
        mode = self.db.get_background_monitor_state("monitor_install_mode", "user")
        active_manager = self.protected_launch_agent if mode in {"protected", "system"} else self.launch_agent
        status = active_manager.status()
        integrity = verify_protected_monitor_integrity(scope="system" if mode in {"protected", "system"} else "user")
        owner_mode_status = "locked down (root:wheel / 644)" if integrity.get("lockdown_compliant") else "user-managed"
        if integrity.get("tamper_detected"):
            owner_mode_status = "tamper detected"
        return {
            "mode": mode,
            "mode_label": "System Monitor Mode" if mode == "system" else ("Protected Mode" if mode == "protected" else "User Mode"),
            "plist_path": status.plist_path or str(active_manager.paths.plist_path),
            "loaded": status.loaded,
            "running": status.running,
            "owner_mode_status": owner_mode_status,
            "integrity_status": "tamper detected" if integrity.get("tamper_detected") else "verified",
            "last_tamper_check": integrity.get("last_checked", ""),
            "integrity": integrity,
        }

    def _refresh_monitor_protection_dialog(self) -> None:
        dialog = getattr(self, "_monitor_protection_dialog", None)
        if dialog is not None:
            dialog.refresh_state(self._monitor_protection_state())

    def _refresh_monitor_mode_dialog(self) -> None:
        dialog = getattr(self, "_monitor_mode_dialog", None)
        if dialog is not None:
            dialog.refresh_state(self._monitor_mode_state())

    def show_monitor_protection_dialog(self) -> None:
        dialog = MonitorProtectionDialog(self, self)
        self._monitor_protection_dialog = dialog
        dialog.refresh_state(self._monitor_protection_state())
        dialog.finished.connect(lambda _result: setattr(self, "_monitor_protection_dialog", None))
        dialog.exec()

    def _monitor_mode_state(self) -> dict[str, object]:
        system_status = self.system_launch_agent.status()
        user_status = self.launch_agent.status()
        integrity = self.system_launch_agent.verify_protected_monitor_integrity()
        return {
            "current_mode": self.db.get_background_monitor_state("monitor_mode", "user"),
            "system_status": f"installed={'yes' if system_status.installed else 'no'} loaded={'yes' if system_status.loaded else 'no'} running={'yes' if system_status.running else 'no'} pid_alive={'yes' if is_pid_alive(system_status.process_pid) else 'no'}",
            "user_status": f"installed={'yes' if user_status.installed else 'no'} loaded={'yes' if user_status.loaded else 'no'} running={'yes' if user_status.running else 'no'} pid_alive={'yes' if is_pid_alive(user_status.process_pid) else 'no'}",
            "system_plist_path": system_status.plist_path,
            "user_plist_path": user_status.plist_path,
            "integrity_status": "tamper detected" if integrity.get("tamper_detected") else "verified",
        }

    def show_monitor_mode_dialog(self) -> None:
        dialog = MonitorModeDialog(self, self)
        self._monitor_mode_dialog = dialog
        dialog.refresh_state(self._monitor_mode_state())
        dialog.finished.connect(lambda _result: setattr(self, "_monitor_mode_dialog", None))
        dialog.exec()

    def _record_protected_monitor_tamper_event(self, integrity: dict[str, object]) -> None:
        if not integrity.get("tamper_detected"):
            return
        event = BackgroundMonitorEvent(
            event_id=f"protected-monitor-tamper-{utc_now_iso()}",
            timestamp=utc_now_iso(),
            event_type="protected_monitor_tamper_detected",
            severity=str(integrity.get("severity", "high")),
            source="integrity_check",
            evidence="; ".join(str(item) for item in integrity.get("evidence", [])),
            confidence=str(integrity.get("confidence", "high")),
            recommendation=str(integrity.get("recommendation", "")),
            metadata_json=json.dumps(integrity, sort_keys=True),
            process_name="com.mac-audit-agent.monitor",
            related_path=str(integrity.get("plist_path", "")),
            related_user="root",
            previous_state="installed and expected" if integrity.get("manifest_exists") else "manifest missing",
            current_state="tampered",
            baseline_status="expected manifest comparison",
            source_trace=str(integrity.get("manifest_path", "")),
        )
        self.db.record_monitor_event(event, notify_force=True)

    def verify_monitor_protection(self) -> None:
        try:
            scope = "system" if self.db.get_background_monitor_state("monitor_install_mode", "user") in {"protected", "system"} else "user"
            integrity = verify_protected_monitor_integrity(scope=scope)
            self.db.set_background_monitor_state("monitor_protection_integrity_json", json.dumps(integrity, sort_keys=True))
            self.db.set_background_monitor_state("monitor_install_mode", "protected" if integrity.get("protected_mode") else "user")
            self.db.set_background_monitor_state("monitor_protection_last_checked", str(integrity.get("last_checked", "")))
            self.db.set_background_monitor_state("monitor_protection_status", "tamper detected" if integrity.get("tamper_detected") else "verified")
            if integrity.get("tamper_detected"):
                self._record_protected_monitor_tamper_event(integrity)
            QMessageBox.information(
                self,
                "Monitor Protection",
                "\n".join(
                    [
                        f"Mode: {'Protected Mode' if integrity.get('protected_mode') else 'User Mode'}",
                        f"Integrity: {'tamper detected' if integrity.get('tamper_detected') else 'verified'}",
                        f"Evidence: {'; '.join(str(item) for item in integrity.get('evidence', [])) or 'none'}",
                    ]
                ),
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Verify Protection Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def lock_down_protected_files(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "Protected Mode Requires Admin", "Locking down protected files requires administrator/root approval.")
            return
        try:
            notes = self.protected_launch_agent.lock_down_protected_files()
            integrity = verify_protected_monitor_integrity(scope="system")
            self.db.set_background_monitor_state("monitor_protection_integrity_json", json.dumps(integrity, sort_keys=True))
            self.db.set_background_monitor_state("monitor_install_mode", "protected" if integrity.get("protected_mode") else "user")
            self.db.set_background_monitor_state("monitor_protection_last_checked", str(integrity.get("last_checked", "")))
            self.db.set_background_monitor_state("monitor_protection_status", "tamper detected" if integrity.get("tamper_detected") else "verified")
            QMessageBox.information(
                self,
                "Protected Files Locked Down",
                "\n".join(notes or ["Protected system files were re-locked."]),
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Lock Down Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def install_protected_mode(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(
                self,
                "Protected Mode Requires Admin",
                "Protected Mode requires administrator/root approval.\n\nRun the app with admin authorization or use the following commands as root:\n"
                f"  chown -R root:wheel /Library/Application Support/MacAuditAgent\n"
                f"  chmod -R go-w /Library/Application Support/MacAuditAgent\n"
                f"  launchctl bootstrap system /Library/LaunchDaemons/{self.protected_launch_agent.paths.plist_path.name}\n"
                f"  launchctl kickstart -k system/{self.protected_launch_agent.paths.plist_path.stem}",
            )
            return
        try:
            plist_path = self.protected_launch_agent.install_protected_mode()
            user_plist_path = self._system_user_notifier_manager().install_user_notifier()
            self.db.set_background_monitor_state("monitor_mode", "protected")
            self.db.set_background_monitor_state("monitor_install_mode", "protected")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("enabled", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("label", self.protected_launch_agent.status().label)
            self.db.set_background_monitor_state("log_path", self.protected_launch_agent.show_logs())
            self.db.set_background_monitor_state("db_path", str(default_monitor_db_path("system")))
            self.db.set_background_monitor_state("current_launchctl_domain", self.protected_launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
            self.verify_monitor_protection()
            QMessageBox.information(
                self,
                "Protected Mode Installed",
                f"Protected system daemon installed at:\n{plist_path}\n\nUser notification companion installed at:\n{user_plist_path}",
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Protected Mode Install Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def repair_protected_mode(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "Protected Mode Requires Admin", "Repairing Protected Mode requires administrator/root approval.")
            return
        try:
            plist_path, notes = self.protected_launch_agent.repair()
            self.db.set_background_monitor_state("monitor_install_mode", "protected")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(self, "Protected Mode Repaired", "\n".join(notes))
            self.verify_monitor_protection()
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Protected Mode Repair Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def uninstall_protected_mode(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "Protected Mode Requires Admin", "Uninstalling Protected Mode requires administrator/root approval.")
            return
        dialog = getattr(self, "_monitor_protection_dialog", None)
        remove_runtime = bool(dialog.remove_runtime_checkbox.isChecked()) if dialog is not None else False
        try:
            self.protected_launch_agent.uninstall_protected_mode(remove_runtime=remove_runtime)
            self.db.set_background_monitor_state("monitor_install_mode", "user")
            for key, value in [("installed", "0"), ("enabled", "0"), ("running", "0"), ("loaded", "0")]:
                self.db.set_background_monitor_state(key, value)
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(self, "Protected Mode Uninstalled", "Protected mode was uninstalled.\nUser mode remains available.")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Protected Mode Uninstall Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def revert_to_user_mode(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "Protected Mode Requires Admin", "Reverting from Protected Mode requires administrator/root approval.")
            return
        try:
            plist_path = self.protected_launch_agent.revert_to_user_mode()
            self.db.set_background_monitor_state("monitor_install_mode", "user")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("enabled", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("label", self.launch_agent.status().label)
            self.db.set_background_monitor_state("log_path", self.launch_agent.show_logs())
            self.db.set_background_monitor_state("db_path", str(self.db.path))
            self.db.set_background_monitor_state("current_launchctl_domain", self.launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(self, "Reverted to User Mode", f"User-mode monitor installed at:\n{plist_path}")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Revert to User Mode Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def install_system_monitor(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "System Monitor Requires Admin", "System Monitor Mode requires administrator/root approval.")
            return
        try:
            plist_path = self.system_launch_agent.install_system_monitor()
            user_plist_path = self._system_user_notifier_manager().install_user_notifier()
            self.db.set_background_monitor_state("monitor_mode", "system")
            self.db.set_background_monitor_state("monitor_install_mode", "system")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("enabled", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("label", self.system_launch_agent.status().label)
            self.db.set_background_monitor_state("log_path", self.system_launch_agent.show_logs())
            self.db.set_background_monitor_state("db_path", str(default_monitor_db_path("system")))
            self.db.set_background_monitor_state("current_launchctl_domain", self.system_launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
            readiness = self._notification_service().test_notification()
            self.db.set_background_monitor_state("notification_readiness_json", json.dumps(readiness, sort_keys=True))
            self.db.set_background_monitor_state("notification_status", self._notification_service().notifications.status())
            QMessageBox.information(
                self,
                "System Monitor Installed",
                f"System daemon installed at:\n{plist_path}\n\nUser notification companion installed at:\n{user_plist_path}",
            )
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Install Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def start_system_monitor(self) -> None:
        try:
            self.system_launch_agent.start()
            self.db.set_background_monitor_state("monitor_mode", "system")
            self.db.set_background_monitor_state("running", "1")
            self.db.set_background_monitor_state("loaded", "1")
            self.db.set_background_monitor_state("current_launchctl_domain", self.system_launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Start Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def stop_system_monitor(self) -> None:
        try:
            self.system_launch_agent.stop()
            self.db.set_background_monitor_state("running", "0")
            self.db.set_background_monitor_state("loaded", "0")
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Stop Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self._refresh_monitor_mode_dialog()
        self.refresh()

    def restart_system_monitor(self) -> None:
        try:
            self.system_launch_agent.stop()
        except Exception:
            pass
        try:
            self.system_launch_agent.start()
            time.sleep(5)
            self.db.set_background_monitor_state("monitor_mode", "system")
            self.refresh()
            QMessageBox.information(self, "System Monitor Restarted", "System Monitor restarted.")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Restart Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self.refresh()

    def repair_system_monitor(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "System Monitor Requires Admin", "Repairing System Monitor requires administrator/root approval.")
            return
        try:
            plist_path, notes = self.system_launch_agent.repair()
            self.db.set_background_monitor_state("monitor_mode", "system")
            self.db.set_background_monitor_state("monitor_install_mode", "system")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(self, "System Monitor Repaired", "\n".join(notes))
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Repair Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self.refresh()

    def uninstall_system_monitor(self) -> None:
        if os.geteuid() != 0:
            QMessageBox.warning(self, "System Monitor Requires Admin", "Uninstalling System Monitor requires administrator/root approval.")
            return
        try:
            self.system_launch_agent.uninstall_protected_mode(remove_runtime=False)
            for key, value in [("monitor_mode", "user"), ("monitor_install_mode", "user"), ("installed", "0"), ("enabled", "0"), ("running", "0"), ("loaded", "0")]:
                self.db.set_background_monitor_state(key, value)
            self.db.set_background_monitor_state("last_error", "")
            QMessageBox.information(self, "System Monitor Uninstalled", "System Monitor was uninstalled.\nUser Notifier remains available.")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "System Monitor Uninstall Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self.refresh()

    def install_user_notifier(self) -> None:
        try:
            plist_path = self.launch_agent.install_user_notifier()
            current_mode = self.db.get_background_monitor_state("monitor_mode", "user")
            if current_mode not in {"protected", "system"}:
                self.db.set_background_monitor_state("monitor_mode", "user")
                self.db.set_background_monitor_state("monitor_install_mode", "user")
            self.db.set_background_monitor_state("installed", "1")
            self.db.set_background_monitor_state("enabled", "1")
            self.db.set_background_monitor_state("plist_path", str(plist_path))
            self.db.set_background_monitor_state("label", self.launch_agent.status().label)
            self.db.set_background_monitor_state("log_path", self.launch_agent.show_logs())
            self.db.set_background_monitor_state("db_path", str(self.db.path))
            self.db.set_background_monitor_state("current_launchctl_domain", self.launch_agent.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
            readiness = self._notification_service().test_notification()
            self.db.set_background_monitor_state("notification_readiness_json", json.dumps(readiness, sort_keys=True))
            self.db.set_background_monitor_state("notification_status", self._notification_service().notifications.status())
            QMessageBox.information(self, "User Notifier Installed", f"User Notifier installed at:\n{plist_path}")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "User Notifier Install Failed", str(exc))
        self._refresh_monitor_protection_dialog()
        self.refresh()

    def test_event_flow(self) -> None:
        event = self._event_service().generate_test_event()
        self._notification_service().process_pending_notifications()
        QMessageBox.information(self, "Test Event Flow", f"Created test event: {event.event_type}")
        self.refresh()

    def refresh(self) -> None:
        monitor_db = self._active_monitor_db()
        try:
            pending_notifications = self._notification_service().process_pending_notifications()
            if pending_notifications:
                self.db.set_background_monitor_state("user_notifier_last_processed", utc_now_iso())
                self.db.set_background_monitor_state("user_notifier_pending_count", str(len(pending_notifications)))
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"Notifier processing failed: {exc}")
        notification_manager = self._notification_service().notifications
        daemon_db_path = str(default_monitor_db_path("system"))
        notifier_db_path = monitor_db.get_background_monitor_state("notifier_db_path", str(monitor_db.path))
        ui_db_path = str(self.db.path)
        db_mismatch = bool(notifier_db_path and notifier_db_path != str(monitor_db.path))
        pipeline_broken = monitor_db.get_background_monitor_state("notification_pipeline_broken", "0") == "1"
        db_status = monitor_db.get_background_monitor_status()
        install_mode = self.db.get_background_monitor_state("monitor_mode", self.db.get_background_monitor_state("monitor_install_mode", "user"))
        if not db_status.installed and install_mode not in {"protected", "system"}:
            install_mode = "user"
        active_launch_agent = self.system_launch_agent if install_mode in {"protected", "system"} else self.launch_agent
        launch_status = active_launch_agent.status()
        system_status = self.system_launch_agent.status()
        user_status = self.launch_agent.status()
        system_mode = install_mode in {"protected", "system"}
        installed = launch_status.installed
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
        if system_mode and not system_status.installed:
            status_text = "system daemon not installed"
        stale_text = "\nMonitor is installed but not actively running." if loaded and not running else ""
        if not loaded and pid_alive:
            stale_text = "\nMonitor process is running outside LaunchAgent. Repair recommended."
        elif installed and not heartbeat_fresh:
            stale_text = "\nMonitor not healthy. Restart Monitor is recommended."
        if system_mode and not system_status.installed:
            stale_text = "\nSystem Monitor Mode requires /Library/LaunchDaemons/com.mac-audit-agent.monitor.plist. Install System Monitor with administrator approval."
        self.status_label.setText(
            f"Status: {status_text} | Installed: {'yes' if installed else 'no'} | Loaded: {'yes' if loaded else 'no'}\n"
            f"System LaunchDaemon plist: {system_status.plist_path} ({'installed' if system_status.installed else 'missing'})\n"
            f"User notifier plist: {user_status.plist_path} ({'installed' if user_status.installed else 'missing'})\n"
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
                    f"Detector enabled hardware: {'yes' if db_status.detector_enabled_hardware else 'no'}",
                    f"Detector last zero reason: {db_status.detector_last_zero_reason or 'none'}",
                    f"Current snapshot: {db_status.current_snapshot or '{}'}",
                    f"Current snapshot keys: {', '.join(sorted(json.loads(db_status.current_snapshot or '{}').keys())) if db_status.current_snapshot else 'none'}",
                    f"Events in last 10 minutes: {db_status.events_last_10_minutes}",
                    f"Suppressed popup count: {self._suppressed_popup_count()}",
                    f"Last notification decision: {self._last_notification_decision()}",
                    f"Notification permission/status: {db_status.notification_status or notification_manager.status()}",
                    f"Notification readiness: {monitor_db.get_background_monitor_state('notification_readiness_json', '{}')}",
                    f"Notification capabilities: {monitor_db.get_background_monitor_state('notification_capabilities_json', '{}')}",
                    f"Last notification test time: {monitor_db.get_background_monitor_state('last_test_time', 'never')}",
                    f"Last notification test result: {monitor_db.get_background_monitor_state('last_test_result', 'none')}",
                    f"Last overlay error: {monitor_db.get_background_monitor_state('last_overlay_error', 'none')}",
                    f"Last dialog error: {monitor_db.get_background_monitor_state('last_dialog_error', 'none')}",
                    f"Last notification error: {monitor_db.get_background_monitor_state('last_notification_error', 'none')}",
                    f"CFAA acknowledgment: {monitor_db.get_background_monitor_state('cfaa_acknowledgment_status', 'not started')}",
                    f"Security overlay: {monitor_db.get_background_monitor_state('security_overlay_status', 'inactive')}",
                    f"Alert overlay enabled: {monitor_db.get_background_monitor_state('show_visible_alerts', '1')}",
                    f"Notifier running: {monitor_db.get_background_monitor_state('notification_status', notification_manager.status())}",
                    f"Notifier health: running={monitor_db.get_background_monitor_state('notifier_running', '0')} pid={monitor_db.get_background_monitor_state('notifier_pid', 'none')} last poll={monitor_db.get_background_monitor_state('notifier_last_poll', 'never')}",
                    f"Notifier installed: {monitor_db.get_background_monitor_state('notifier_installed', '0')}",
                    f"Notifier loaded: {monitor_db.get_background_monitor_state('notifier_loaded', '0')}",
                    f"Notifier PID alive: {monitor_db.get_background_monitor_state('notifier_pid_alive', '0')}",
                    f"Daemon DB path: {daemon_db_path}",
                    f"Notifier DB path: {notifier_db_path}",
                    f"UI DB path: {ui_db_path}",
                    f"DB path alignment: {'mismatch' if db_mismatch else 'aligned'}",
                    f"Notifier last event seen: {monitor_db.get_background_monitor_state('notifier_last_event_seen', 'never')}",
                    f"Notifier last alert displayed: {monitor_db.get_background_monitor_state('notifier_last_alert_displayed', monitor_db.get_background_monitor_state('last_alert_displayed_at', 'never'))}",
                    f"Notifier cursor before: {monitor_db.get_background_monitor_state('notifier_cursor_before', 'none')}",
                    f"Notifier cursor after: {monitor_db.get_background_monitor_state('notifier_cursor_after', 'none')}",
                    f"Last alert displayed at: {monitor_db.get_background_monitor_state('last_alert_displayed_at', 'never')}",
                    f"Last alert decision: {monitor_db.get_background_monitor_state('last_alert_decision', 'none')}",
                    f"Suppressed alert count: {monitor_db.get_background_monitor_state('suppressed_alert_count', '0')}",
                    f"Last suppression reason: {monitor_db.get_background_monitor_state('last_suppression_reason', 'none')}",
                    f"Overlay manager status: {monitor_db.get_background_monitor_state('security_overlay_status', 'inactive')}",
                    f"Overlay manager alive: {monitor_db.get_background_monitor_state('overlay_manager_alive', monitor_db.get_background_monitor_state('overlay_alive', '0'))}",
                    f"Overlay alive: {monitor_db.get_background_monitor_state('overlay_alive', monitor_db.get_background_monitor_state('overlay_manager_alive', '0'))}",
                    f"Overlay dispatch result: {monitor_db.get_background_monitor_state('overlay_dispatch_result', 'unknown')}",
                    f"Overlay error count: {monitor_db.get_background_monitor_state('overlay_error_count', '0')}",
                    f"Last overlay exception: {monitor_db.get_background_monitor_state('last_overlay_exception', monitor_db.get_background_monitor_state('last_overlay_error', 'none'))}",
                    f"Last overlay error: {monitor_db.get_background_monitor_state('last_overlay_error', monitor_db.get_background_monitor_state('last_overlay_exception', 'none'))}",
                    f"Queue before: {monitor_db.get_background_monitor_state('alert_queue_length_before', '0')}",
                    f"Queue after: {monitor_db.get_background_monitor_state('alert_queue_length_after', '0')}",
                    f"Alert queue length: {monitor_db.get_background_monitor_state('alert_queue_length', monitor_db.get_background_monitor_state('queue_length', str(len(monitor_db.pending_background_monitor_events(limit=200)))))}",
                    f"Notification pipeline: {'broken' if pipeline_broken or db_mismatch else 'ok'}",
                    f"Self-impact watchdog level: {monitor_db.get_background_monitor_state('self_impact_level', 'not checked')}",
                    f"Self-impact watchdog score: {monitor_db.get_background_monitor_state('self_impact_score', '0')}/100",
                    f"Self-impact bounded polling backoff: {monitor_db.get_background_monitor_state('self_impact_backoff_multiplier', '1')}x",
                    f"Self-impact metrics: {monitor_db.get_background_monitor_state('self_impact_metrics_json', '{}')}",
                    f"Current mode: {'System Monitor Mode' if install_mode == 'system' else ('Protected Mode' if install_mode == 'protected' else 'User Monitor Mode')}",
                    f"System LaunchDaemon plist: {system_status.plist_path} ({'installed' if system_status.installed else 'missing'})",
                    f"User notifier plist: {user_status.plist_path} ({'installed' if user_status.installed else 'missing'})",
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
        settings = notification_manager.settings()
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
        self.show_visible_alerts_checkbox.setChecked(bool(settings.get("show_visible_alerts", True)))
        self.show_physical_session_alerts_checkbox.setChecked(bool(settings.get("show_physical_session_alerts", True)))
        self.show_usb_bluetooth_alerts_checkbox.setChecked(bool(settings.get("show_usb_bluetooth_alerts", True)))
        self.show_network_change_alerts_checkbox.setChecked(bool(settings.get("show_network_change_alerts", True)))
        self.show_admin_persistence_alerts_checkbox.setChecked(bool(settings.get("show_admin_persistence_alerts", True)))
        self.show_apple_forecast_alerts_checkbox.setChecked(bool(settings.get("show_apple_forecast_alerts", True)))
        self.idle_warning_minutes_input.setText(str(settings.get("idle_activity_warning_minutes", 2)))
        self.cfaa_idle_warning_checkbox.setChecked(bool(settings.get("cfaa_idle_warning_enabled", True)))
        self.cooldown_seconds_input.setText(str(settings.get("cooldown_seconds_per_category", 600)))
        current_severity = str(settings["notify_min_severity"])
        index = self.notify_min_severity_combo.findData(current_severity)
        if index >= 0:
            self.notify_min_severity_combo.setCurrentIndex(index)
        mode_index = self.notification_mode_combo.findData(str(settings.get("notification_mode", "notification")))
        if mode_index >= 0:
            self.notification_mode_combo.setCurrentIndex(mode_index)
        self.rate_limit_input.setText(str(settings["duplicate_rate_limit_seconds"]))
        self.notification_sound_input.setText(str(settings["notification_sound"]))
        installed_state = ActionState(
            bool(installed),
            True,
            "Install the background monitor before using this action.",
            ["installed background monitor"],
        )
        for button in [self.start_button, self.stop_button, self.uninstall_button, self.restart_button]:
            apply_action_state(button, installed_state)
        self.refresh_events()

    def refresh_events(self) -> None:
        event_type = str(self.filter_combo.currentData() or "")
        monitor_db = self._active_monitor_db()
        events = monitor_db.latest_monitor_events(limit=200) if not event_type else monitor_db.recent_background_monitor_events(limit=200, event_type=event_type)
        self.current_events = list(events)
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
                    self._event_occurrence_label(event),
                    event.evidence,
                ]
            ):
                self.events_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.events_table.resizeRowsToContents()
        self._update_selected_event_context_state()

    def _event_occurrence_label(self, event: BackgroundMonitorEvent) -> str:
        count = max(1, int(getattr(event, "occurrence_count", 1) or 1))
        duplicate_category = str(getattr(event, "duplicate_category", "single") or "single")
        if count <= 1:
            return "1"
        return f"{count} ({duplicate_category.replace('_', ' ')})"

    def _selected_event(self):
        if not hasattr(self, "events_table"):
            return None
        selected = self.events_table.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        if row < 0 or row >= len(self.current_events):
            return None
        return self.current_events[row]

    def _update_selected_event_context_state(self) -> None:
        if not hasattr(self, "show_context_button"):
            return
        enabled = self._selected_event() is not None
        state = ActionState(enabled, enabled, "Select a monitor event first.", ["selected monitor event"])
        apply_action_state(self.show_context_button, state)
        if hasattr(self, "show_provenance_button"):
            apply_action_state(self.show_provenance_button, state)
        if hasattr(self, "show_alert_trace_button"):
            apply_action_state(self.show_alert_trace_button, state)

    def show_selected_event_context(self) -> None:
        event = self._selected_event()
        if event is None:
            QMessageBox.information(self, "No Event", "Select an event first.")
            return
        window = self.workflow_layer.build_context_window(
            event.timestamp,
            focus_label=event.event_type,
            focus_kind="monitor",
            focus_category="monitor",
            focus_id=event.event_id,
            focus_event_id=event.event_id,
        )
        ContextDialog(window, self).exec()

    def _selected_event_provenance_text(self, event) -> str:
        hints = event.false_positive_hints or []
        steps = event.recommended_verification_steps or []
        lines = [
            f"Alert: {event.event_type}",
            f"Rule: {event.rule_id or event.trigger_rule_id} ({event.rule_name or event.trigger_rule_name})",
            f"Detector: {event.trigger_source or event.source} / {event.trigger_subsource or event.source}",
            f"Confidence: {event.confidence}",
            f"Evidence: {event.evidence}",
            f"Previous state: {event.previous_state}",
            f"Current state: {event.current_state}",
            f"First seen: {event.first_seen or event.timestamp}",
            f"Last seen: {event.last_seen or event.timestamp}",
            f"Correlation: {event.correlation_id}",
            f"Baseline: {event.baseline_status}",
            f"Possible false-positive reason: {', '.join(str(item) for item in hints) if hints else event.suppression_reason}",
            f"Verification: {', '.join(str(item) for item in steps) if steps else event.recommendation}",
        ]
        if event.raw_signal_summary:
            lines.append(f"Raw signal: {event.raw_signal_summary}")
        if event.normalized_signal:
            lines.append(f"Normalized signal: {event.normalized_signal}")
        if event.source_trace:
            lines.append(f"Source trace: {event.source_trace}")
        if event.evidence_hash:
            lines.append(f"Evidence hash: {event.evidence_hash}")
        return "\n".join(line for line in lines if line)

    def show_selected_event_provenance(self) -> None:
        event = self._selected_event()
        if event is None:
            QMessageBox.information(self, "No Event", "Select an event first.")
            return
        window = self.workflow_layer.build_context_window(
            event.timestamp,
            focus_label=event.event_type,
            focus_kind="monitor",
            focus_category="monitor",
            focus_id=event.event_id,
            focus_event_id=event.event_id,
        ).to_dict()
        body = self._selected_event_provenance_text(event)
        AlertProvenanceDialog("Alert Provenance", body, window, self).exec()

    def _selected_event_trace_text(self, event) -> str:
        trace = self._active_monitor_db().get_event_alert_trace(event.event_id)
        if trace is None:
            return f"Alert Pipeline Trace\nNo trace exists yet for event_id={event.event_id}."
        lines = [
            "Alert Pipeline Trace",
            f"trace_id: {trace.trace_id}",
            f"event_id: {trace.event_id}",
            f"event_type: {trace.event_type}",
            f"original_event_type: {trace.original_event_type or 'none'}",
            f"normalized_event_type: {trace.normalized_event_type or 'none'}",
            f"detector_source: {trace.detector_source or 'unknown'}",
            f"stored_db_path: {trace.stored_db_path or 'unknown'}",
            f"stored_success: {'yes' if trace.stored_success else 'no'}",
            f"notifier_db_path: {trace.notifier_db_path or 'unknown'}",
            f"notifier_seen: {'yes' if trace.notifier_seen else 'no'}",
            f"notifier_seen_at: {trace.notifier_seen_at or 'never'}",
            f"notification_policy_checked: {'yes' if trace.notification_policy_checked else 'no'}",
            f"notification_policy_result: {trace.notification_policy_result or 'unknown'}",
            f"notification_policy_reason: {trace.notification_policy_reason or 'none'}",
            f"severity_before_policy: {trace.severity_before_policy or 'unknown'}",
            f"severity_after_policy: {trace.severity_after_policy or 'unknown'}",
            f"alert_required: {'yes' if trace.alert_required else 'no'}",
            f"alert_suppressed: {'yes' if trace.alert_suppressed else 'no'}",
            f"alert_suppression_reason: {trace.alert_suppression_reason or 'none'}",
            f"overlay_dispatch_attempted: {'yes' if trace.overlay_dispatch_attempted else 'no'}",
            f"overlay_dispatch_at: {trace.overlay_dispatch_at or 'never'}",
            f"overlay_dispatch_result: {trace.overlay_dispatch_result or 'unknown'}",
            f"overlay_error: {trace.overlay_error or 'none'}",
            f"visible_alert_id: {trace.visible_alert_id or 'none'}",
        ]
        return "\n".join(lines)

    def show_selected_alert_pipeline_trace(self) -> None:
        event = self._selected_event()
        if event is None:
            QMessageBox.information(self, "No Event", "Select an event first.")
            return
        window = self.workflow_layer.build_context_window(
            event.timestamp,
            focus_label=event.event_type,
            focus_kind="monitor",
            focus_category="monitor",
            focus_id=event.event_id,
            focus_event_id=event.event_id,
        ).to_dict()
        body = self._selected_event_trace_text(event)
        AlertProvenanceDialog("Alert Pipeline Trace", body, window, self).exec()

    def install_monitor(self) -> None:
        if QMessageBox.question(
            self,
            "Install System Monitor + User Notifier",
            f"{DISCLAIMER}\n\n"
            "The detector will be installed as a root-owned system LaunchDaemon under /Library/LaunchDaemons. "
            "A user LaunchAgent companion will also be installed for GUI notifications after login.",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.install_system_monitor()

    def toggle_continuous_monitoring(self, enabled: bool) -> None:
        try:
            mode = self.db.get_background_monitor_state("monitor_mode", "user")
            if enabled:
                if mode in {"protected", "system"}:
                    if not self.system_launch_agent.status().installed:
                        raise RuntimeError("System monitor is not installed. Install the system daemon with administrator approval first.")
                    self.system_launch_agent.start()
                    if self.launch_agent.status().installed:
                        self.launch_agent.start()
                else:
                    if not self.launch_agent.status().installed:
                        raise RuntimeError("System monitor is not installed. Use Install System Monitor + User Notifier first.")
                    self.launch_agent.start()
                deadline = time.monotonic() + 10
                heartbeat_updated = False
                detector_updated = False
                monitor_db = self._active_monitor_db()
                baseline = monitor_db.get_background_monitor_status()
                needs_detector = self.db.get_background_monitor_state("monitor_mode", "user") in {"system", "protected"}
                while time.monotonic() < deadline:
                    current = monitor_db.get_background_monitor_status()
                    heartbeat_updated = bool(current.last_heartbeat and current.last_heartbeat != baseline.last_heartbeat)
                    detector_updated = bool(current.detector_last_run_timestamp and current.detector_last_run_timestamp != baseline.detector_last_run_timestamp)
                    if heartbeat_updated and (detector_updated or not needs_detector):
                        break
                    time.sleep(1)
                self.db.set_background_monitor_state("enabled", "1")
                if not (heartbeat_updated and (detector_updated or not needs_detector)):
                    QMessageBox.warning(
                        self,
                        "Continuous Monitoring",
                        "LaunchAgent started, but heartbeat or detector loop did not update within 10 seconds."
                        if needs_detector
                        else "LaunchAgent started, but heartbeat did not update within 10 seconds.",
                    )
            else:
                if mode in {"protected", "system"}:
                    self.system_launch_agent.stop()
                if self.launch_agent.status().installed:
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
                install_helper = getattr(self.launch_agent, "install_user_notifier", self.launch_agent.install)
                install_helper()
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

    def audit_system_monitor_deployment(self) -> None:
        try:
            report = self.system_readiness.audit_deployment()
            self.deployment_audit_panel.setPlainText(report.render_text())
            self.db.set_background_monitor_state("deployment_audit_last_report_json", json.dumps(report.to_dict(), sort_keys=True))
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"deployment audit failed: {exc}")
            self.deployment_audit_panel.setPlainText(f"Deployment Audit Report\n[FAIL] Unable to audit System Monitor deployment: {exc}")
            QMessageBox.warning(self, "Deployment Audit Failed", str(exc))
        self.refresh()

    def verify_system_monitor_event_flow(self) -> None:
        try:
            result = self.system_readiness.verify_event_flow(timeout_seconds=10)
            self.deployment_audit_panel.setPlainText(result.render_text())
            self.db.set_background_monitor_state("deployment_event_flow_last_report_json", json.dumps(result.to_dict(), sort_keys=True))
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"event flow verification failed: {exc}")
            self.deployment_audit_panel.setPlainText(f"Event Pipeline Verification\n[FAIL] Unable to verify event flow: {exc}")
            QMessageBox.warning(self, "Event Flow Verification Failed", str(exc))
        self.refresh()

    def repair_system_monitor_deployment(self) -> None:
        try:
            report = self.system_readiness.audit_deployment()
        except Exception as exc:
            QMessageBox.warning(self, "Repair Audit Failed", str(exc))
            return
        if not report.repair_actions:
            self.deployment_audit_panel.setPlainText(report.render_text())
            QMessageBox.information(self, "System Monitor Deployment", "No deployment repair actions are required.")
            return
        actions_text = "\n".join(f"- {action}" for action in report.repair_actions)
        message = (
            "Repair System Monitor Deployment will only run after administrator approval.\n\n"
            "Planned actions:\n"
            f"{actions_text}\n\n"
            "This may update the LaunchDaemon plist/runtime, restart the daemon, and reinstall the user notifier if missing. "
            "Reports, snapshots, notes, and monitor history are preserved."
        )
        answer = QMessageBox.question(
            self,
            "Repair System Monitor Deployment",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            self.deployment_audit_panel.setPlainText(report.render_text() + "\n\nRepair cancelled by user.")
            return
        try:
            notes = self.system_readiness.repair_mismatches(report)
            rerun = self.system_readiness.audit_deployment()
            self.deployment_audit_panel.setPlainText("\n".join(["Repair Results", *notes, "", rerun.render_text()]))
            QMessageBox.information(self, "System Monitor Deployment Repaired", "\n".join(notes))
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"deployment repair failed: {exc}")
            self.deployment_audit_panel.setPlainText(report.render_text() + f"\n\n[FAIL] Repair failed: {exc}")
            QMessageBox.warning(self, "Deployment Repair Failed", str(exc))
        self.refresh()

    def repair_monitor(self) -> None:
        try:
            stopped = self.service.stop_orphan_processes()
            manager = self._detector_manager()
            plist_path, notes = manager.repair()
            if self._system_mode_enabled():
                self._system_user_notifier_manager().install_user_notifier()
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

    def repair_alerts_notifier(self) -> None:
        manager = self._notifier_manager()
        notifier_service = self._notification_service()
        monitor_db = self._active_monitor_db()

        def fail(stage: str, exc: Exception | str) -> None:
            tail = self._repair_alerts_log_tail()
            detail = f"Repair Alerts / Notifier failed at stage: {stage}\n{exc}\n\nStderr/log tail:\n{tail}"
            monitor_db.set_background_monitor_state("notifier_last_error", detail)
            monitor_db.set_background_monitor_state("last_overlay_error", detail)
            monitor_db.set_background_monitor_state("last_error", detail)
            QMessageBox.warning(self, "Repair Alerts / Notifier Failed", detail)
            self.refresh()

        try:
            stopped_orphans = self.service.stop_orphan_processes()
        except Exception as exc:
            fail("kill orphan notifier processes", exc)
            return
        try:
            manager.stop()
        except Exception as exc:
            fail("stop user notifier LaunchAgent", exc)
            return
        try:
            manager.uninstall()
        except Exception as exc:
            fail("remove old notifier plist", exc)
            return
        try:
            plist_path = manager.install_user_notifier()
        except Exception as exc:
            fail("recreate notifier plist", exc)
            return
        try:
            manager.start()
        except Exception as exc:
            fail("bootstrap/kickstart notifier", exc)
            return
        try:
            status = manager.status()
            pid_alive = is_pid_alive(status.process_pid)
            if not pid_alive:
                raise RuntimeError(status.last_error or f"Notifier PID not alive: {status.process_pid or 'none'}")
            monitor_db.set_background_monitor_state("notifier_installed", "1")
            monitor_db.set_background_monitor_state("notifier_loaded", "1" if status.loaded else "0")
            monitor_db.set_background_monitor_state("notifier_pid_alive", "1" if pid_alive else "0")
            monitor_db.set_background_monitor_state("notifier_db_path", str(notifier_service.db.path))
            monitor_db.set_background_monitor_state("notifier_last_poll", utc_now_iso())
            monitor_db.set_background_monitor_state("notifier_last_alert_displayed", monitor_db.get_background_monitor_state("notifier_last_alert_displayed", ""))
            monitor_db.set_background_monitor_state("notifier_last_error", "")
        except Exception as exc:
            fail("verify notifier PID alive", exc)
            return
        try:
            test_event = notifier_service.simulate_event(
                "camera_activity_stopped",
                "Repair Alerts / Notifier synthetic overlay test alert.",
                severity="info",
                confidence="high",
                source="repair_alerts",
                process_name="FaceTime",
                pid=0,
                notify_force=False,
            )
            notifier_service.process_pending_notifications()
            monitor_db.set_background_monitor_state("notifier_last_event_seen", test_event.timestamp)
            monitor_db.set_background_monitor_state("alert_queue_length", str(len(monitor_db.pending_background_monitor_events(limit=200))))
        except Exception as exc:
            fail("generate test event", exc)
            return
        try:
            latest_events = monitor_db.latest_monitor_events(limit=10)
            matched = next((event for event in latest_events if event.event_id == test_event.event_id), None)
            if matched is None:
                raise RuntimeError("synthetic test event not found in database")
            if not matched.notification_sent:
                raise RuntimeError("synthetic test event was not consumed by the notifier")
            if not matched.visible_alert_shown:
                raise RuntimeError("synthetic test event did not produce a visible alert")
            if monitor_db.get_background_monitor_state("overlay_manager_alive", "0") != "1":
                raise RuntimeError("overlay manager is not reported as alive")
            if monitor_db.get_background_monitor_state("overlay_dispatch_result", "") not in {"SUCCESS", "skipped"}:
                raise RuntimeError(
                    f"overlay dispatch did not succeed: {monitor_db.get_background_monitor_state('overlay_dispatch_result', 'unknown')}"
                )
        except Exception as exc:
            fail("verify test event consumed and overlay displayed", exc)
            return
        monitor_db.set_background_monitor_state("last_error", "")
        QMessageBox.information(
            self,
            "Repair Alerts / Notifier",
            "\n".join(
                [
                    "Repair Alerts / Notifier completed.",
                    f"Stopped orphan processes: {stopped_orphans or 'none'}",
                    f"Recreated notifier plist: {plist_path}",
                    f"Notifier PID alive: {manager.status().process_pid or 'none'}",
                    "Synthetic test alert was consumed and displayed.",
                ]
            ),
        )
        self.refresh()

    def force_reinstall_monitor(self) -> None:
        try:
            stopped = self.service.stop_orphan_processes()
            manager = self._detector_manager()
            plist_path, notes = manager.force_reinstall()
            if self._system_mode_enabled():
                self._system_user_notifier_manager().install_user_notifier()
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
        manager = self._detector_manager()
        try:
            manager.stop()
            if self._system_mode_enabled() and self.launch_agent.status().installed:
                self.launch_agent.stop()
        except Exception:
            pass
        try:
            manager.start()
            if self._system_mode_enabled() and self.launch_agent.status().installed:
                self.launch_agent.start()
            time.sleep(5)
            self.refresh()
            launch_status = manager.status()
            db_status = self._active_monitor_db().get_background_monitor_status()
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
            manager = self._detector_manager()
            manager.start()
            if self._system_mode_enabled() and self.launch_agent.status().installed:
                self.launch_agent.start()
            self.db.set_background_monitor_state("running", "1")
            self.db.set_background_monitor_state("loaded", "1")
            self.db.set_background_monitor_state("current_launchctl_domain", manager.status().current_launchctl_domain)
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Start Failed", str(exc))
        self.refresh()

    def stop_monitor(self) -> None:
        try:
            manager = self._detector_manager()
            manager.stop()
            if self._system_mode_enabled() and self.launch_agent.status().installed:
                self.launch_agent.stop()
            self.db.set_background_monitor_state("running", "0")
            self.db.set_background_monitor_state("loaded", "0")
            self.db.set_background_monitor_state("last_error", "")
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", str(exc))
            QMessageBox.warning(self, "Stop Failed", str(exc))
        self.refresh()

    def uninstall_monitor(self) -> None:
        manager = self._detector_manager()
        try:
            manager.stop()
        except Exception:
            pass
        if self._system_mode_enabled():
            manager.uninstall_protected_mode(remove_runtime=False)
        else:
            manager.uninstall()
        try:
            self.launch_agent.stop()
        except Exception:
            pass
        self.launch_agent.uninstall()
        for key, value in [("installed", "0"), ("enabled", "0"), ("running", "0"), ("loaded", "0")]:
            self.db.set_background_monitor_state(key, value)
        self.db.set_background_monitor_state("monitor_mode", "user")
        self.db.set_background_monitor_state("monitor_install_mode", "user")
        self.refresh()

    def run_self_test(self) -> None:
        event = self._event_service().run_self_test()
        QMessageBox.information(self, "Self-Test Logged", f"Created event: {event.event_type}")
        self.refresh()

    def run_detectors_once(self) -> None:
        events = self._event_service().run_once()
        QMessageBox.information(self, "Detectors Completed", f"Recorded {len(events)} events to {self.db.path}")
        self.refresh()

    def generate_test_event(self) -> None:
        event = self._event_service().generate_test_event()
        QMessageBox.information(self, "Test Event Logged", f"Created event: {event.event_type}\nDB: {self.db.path}")
        self.refresh()

    def test_bottom_right_alert(self) -> None:
        try:
            service = self._event_service()
            tests = [
                ("protected_monitor_tamper_detected", "Critical bottom-right alert test", "critical", "critical_red"),
                ("usb_device_connected", "High bottom-right alert test", "high", "high_orange"),
                ("apple_security_forecast_elevated", "Neutral bottom-right alert test", "info", "neutral_grey"),
            ]
            for event_type, evidence, severity, expected_style in tests:
                event = BackgroundMonitorEvent(
                    event_id=f"test-{event_type}-{utc_now_iso()}",
                    timestamp=utc_now_iso(),
                    event_type=event_type,
                    evidence=evidence,
                    severity=severity,
                    source="alert_test",
                    process_name="alert_test",
                    pid=0,
                    confidence="high",
                    recommendation="Review the timeline.",
                    rule_id=event_type,
                    rule_name=event_type,
                    trigger_rule_id=event_type,
                    trigger_rule_name=event_type,
                    trigger_source="alert_test",
                )
                service.db.record_monitor_event(event, dedupe_window_seconds=0)
                service.notifications.show_visible_security_alert(event, reason="test_bottom_right_alert")
                event.visible_alert_shown = True
                event.notification_sent = True
                event.notification_decision = "sent"
                event.notification_reason = "test_bottom_right_alert"
                event.popup_allowed = True
                event.alert_style = expected_style
                service.db.update_monitor_event_notification(
                    event.event_id,
                    notification_sent=True,
                    notification_error="",
                    notification_returncode=0,
                    notification_decision="sent",
                    notification_reason="test_bottom_right_alert",
                    cooldown_remaining_seconds=0,
                    popup_allowed=True,
                    visible_alert_shown=True,
                    alert_style=expected_style,
                    cooldown_suppressed=False,
                    last_suppression_reason="",
                )
            QMessageBox.information(self, "Bottom-Right Alert Test", "Generated critical, high, and neutral visible alert test events.")
        except Exception as exc:
            QMessageBox.warning(self, "Bottom-Right Alert Test Failed", str(exc))
        self.refresh()

    def test_critical_alert(self) -> None:
        try:
            event = self._event_service().simulate_event(
                "protected_monitor_tamper_detected",
                "Critical alert test for the notifier repair workflow.",
                severity="critical",
                confidence="high",
                process_name="alert_test",
                pid=0,
                notify_force=True,
            )
            self._notification_service().process_pending_notifications()
            QMessageBox.information(self, "Critical Alert Test", f"Created event: {event.event_type}")
        except Exception as exc:
            QMessageBox.warning(self, "Critical Alert Test Failed", str(exc))
        self.refresh()

    def test_idle_activity_warning(self) -> None:
        try:
            event = self._event_service().simulate_event(
                "input_activity_resumed_after_idle",
                "Activity was detected after a period of inactivity. If this system is under investigation, preserve logs and review the timeline before cleanup or shutdown.",
                severity="medium",
                confidence="high",
                process_name="hid_idle_time",
                pid=0,
                notify_force=True,
            )
            self._notification_service().process_pending_notifications()
            QMessageBox.information(self, "Idle Activity Warning", f"Created event: {event.event_type}")
        except Exception as exc:
            QMessageBox.warning(self, "Idle Activity Warning Failed", str(exc))
        self.refresh()

    def test_notification(self) -> None:
        result = self._notification_service().test_notification()
        QMessageBox.information(
            self,
            "Test Notification",
            "\n".join(
                [
                    f"Overlay: {'PASS' if result.get('overlay', {}).get('success') else 'FAIL'}",
                    f"Dialog: {'PASS' if result.get('dialog', {}).get('success') else 'FAIL'}",
                    f"Notification Center: {'PASS' if result.get('notification_center', {}).get('success') else 'FAIL'}",
                    f"Overall Status: {result.get('overall_status') or ('PASS' if result.get('success') else 'FAIL')}",
                    f"Reason: {result.get('reason') or ('Security alerts remain operational.' if result.get('success') else 'All alert mechanisms failed.')}",
                    f"Overlay error: {result.get('overlay', {}).get('error') or 'none'}",
                    f"Dialog error: {result.get('dialog', {}).get('error') or 'none'}",
                    f"Notification Center error: {result.get('notification_center', {}).get('error') or 'none'}",
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
            self._notification_service().notifications.update_settings(
                notify_all_events=self.notify_all_checkbox.isChecked(),
                notify_important_events=self.notify_important_checkbox.isChecked(),
                notify_min_severity=str(self.notify_min_severity_combo.currentData() or "info"),
                notification_sound=self.notification_sound_input.text().strip() or "Glass",
                duplicate_rate_limit_seconds=int(self.rate_limit_input.text().strip() or "10"),
                high_priority_alert_style=str(self.notification_mode_combo.currentData() or "dialog"),
                notification_mode=str(self.notification_mode_combo.currentData() or "dialog"),
                popup_only_severe_events=self.popup_only_severe_checkbox.isChecked(),
                browser_capture_process_popup=self.browser_capture_popup_checkbox.isChecked(),
                show_visible_alerts=self.show_visible_alerts_checkbox.isChecked(),
                show_physical_session_alerts=self.show_physical_session_alerts_checkbox.isChecked(),
                show_usb_bluetooth_alerts=self.show_usb_bluetooth_alerts_checkbox.isChecked(),
                show_network_change_alerts=self.show_network_change_alerts_checkbox.isChecked(),
                show_admin_persistence_alerts=self.show_admin_persistence_alerts_checkbox.isChecked(),
                show_apple_forecast_alerts=self.show_apple_forecast_alerts_checkbox.isChecked(),
                idle_activity_warning_minutes=int(self.idle_warning_minutes_input.text().strip() or "2"),
                cfaa_idle_warning_enabled=self.cfaa_idle_warning_checkbox.isChecked(),
                cooldown_seconds_per_category=int(self.cooldown_seconds_input.text().strip() or "600"),
            )
            self._active_monitor_db().set_background_monitor_state("notification_status", self._notification_service().notifications.status())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Notification Settings", str(exc))
        self.refresh()

    def _suppressed_popup_count(self) -> int:
        total = 0
        rows = self._active_monitor_db().conn.execute(
            "SELECT value FROM background_monitor_state WHERE key LIKE 'suppressed_notification_count:%'"
        ).fetchall()
        for row in rows:
            try:
                total += int(row["value"] or 0)
            except (TypeError, ValueError):
                continue
        return total

    def _last_notification_decision(self) -> str:
        events = self._active_monitor_db().recent_background_monitor_events(limit=1)
        if not events:
            return "none"
        event = events[0]
        return (
            f"{event.event_type}: {event.notification_decision} "
            f"({event.notification_reason or 'no reason'}) "
            f"popup_allowed={'yes' if event.popup_allowed else 'no'}"
        )

    def show_event_priorities_dialog(self) -> None:
        preferences = self._notification_service().notifications.event_preferences()
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
        self._notification_service().notifications.update_event_preferences(updated)
        self.refresh()

    def _simulate(self, event_type: str, evidence: str, *, severity: str = "info", confidence: str = "high", process_name: str = "", pid: int | None = None) -> None:
        event = self._event_service().simulate_event(
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
        mode = self.db.get_background_monitor_state("monitor_install_mode", "user")
        active_manager = self.system_launch_agent if mode in {"protected", "system"} else self.launch_agent
        path = (
            f"LaunchAgent stdout log: {active_manager.show_logs()}\n"
            f"LaunchAgent stderr log: {self._stderr_log_path()}\n"
            f"Fallback monitor log: {self._fallback_log_path_text()}"
        )
        QMessageBox.information(self, "Monitor Logs", path)

    def test_silent_log_event(self) -> None:
        event = self._event_service().simulate_event(
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
            for path in self._monitor_log_paths():
                truncate_monitor_log_file(path)
            removed = 0
            if clear_db:
                active_db = self._active_monitor_db()
                removed = active_db.clear_monitor_events()
                if active_db.path != self.db.path:
                    removed += self.db.clear_monitor_events()
            self._event_service()._write_log_line("Monitor logs cleared by user.")
            self._write_app_log("Monitor logs cleared by user.")
            if clear_db:
                self._event_service()._write_log_line("Monitor event history cleared by user.")
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
        mode = self.db.get_background_monitor_state("monitor_install_mode", "user")
        active_manager = self.system_launch_agent if mode in {"protected", "system"} else self.launch_agent
        stdout_path = Path(active_manager.show_logs()).expanduser()
        stderr_path = getattr(getattr(active_manager, "paths", None), "stderr_path", default_paths.stderr_path)
        return [FALLBACK_MONITOR_LOG.expanduser(), stdout_path, Path(stderr_path).expanduser()]

    def _write_app_log(self, message: str) -> None:
        path = self.db.logs_dir / "app.log"
        try:
            append_monitor_log_line(path, f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}\n")
        except OSError:
            LOGGER.exception("Failed to append app log line: %s", path)

    def show_detector_snapshot(self) -> None:
        snapshot = self._event_service().collect_detector_snapshot()
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
