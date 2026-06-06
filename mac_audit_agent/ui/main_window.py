from __future__ import annotations

import json
import logging
import random
import subprocess
import shlex
from datetime import datetime
from pathlib import Path
import sys
from typing import Callable
from PySide6.QtCore import QObject, QPointF, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QBrush, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QSizePolicy,
    QListWidgetItem,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.assets import get_asset_path
from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.command_registry import build_command_registry
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.launch_agent import LaunchAgentManager, default_monitor_db_path
from mac_audit_agent.models import AuditCommand, RawLogEntry, ScanResult, ScanSummary, utc_now_iso
from mac_audit_agent.models import Finding, InvestigationNote, NetworkDiscoveryResult, NetworkHostSnapshot
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.network_discovery import (
    SCAN_PROFILES,
    detect_preferred_interface,
    detect_network_scope,
    list_local_interfaces as list_network_interfaces,
    sanitize_interface_name as sanitize_network_interface_name,
)
from mac_audit_agent.packet_capture import (
    MAX_CAPTURE_DURATION_SECONDS,
    PacketCaptureSession,
    default_evidence_dir,
    list_capture_interfaces,
    sanitize_capture_filter,
    sanitize_interface_name,
    tcpdump_available,
    validate_capture_duration,
)
from mac_audit_agent.reporting import (
    SEVERITY_COLOR_MAP,
    default_html_report_path,
    export_investigation_notes_html,
    export_investigation_notes_json,
    default_json_report_path,
    export_scan_result_html,
    export_scan_result_json,
    get_reports_dir,
)
from mac_audit_agent.investigation_priority import InvestigationPriorityEngine
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase, json_safe
from mac_audit_agent.cve_radar import CveRadarEngine
from mac_audit_agent.execution_evidence import ExecutionEvidenceEngine
from mac_audit_agent.family_safety import FamilySafetyAuditor, export_family_safety_html, export_family_safety_json
from mac_audit_agent.intrusion_correlation import IntrusionCorrelationEngine
from mac_audit_agent.operational_health import OperationalHealthEngine
from mac_audit_agent.ui.action_state import ActionState, apply_action_state
from mac_audit_agent.ui.family_safety_panel import FamilySafetyPanel
from mac_audit_agent.ui.investigation_priority_panel import InvestigationPriorityPanel
from mac_audit_agent.ui.context_dialog import ContextDialog
from mac_audit_agent.ui.provenance_dialog import AlertProvenanceDialog
from mac_audit_agent.ui.cve_radar_panel import CveRadarDetailsDialog, CveRadarPanel, make_forecast_button
from mac_audit_agent.ui.flight_recorder_panel import FlightRecorderPanel
from mac_audit_agent.ui.intrusion_detection_panel import IntrusionDetectionPanel
from mac_audit_agent.ui.logs_panel import LogsPanel
from mac_audit_agent.ui.operational_health_panel import OperationalHealthPanel
from mac_audit_agent.ui.system_recovery_panel import RecoveryEvidenceWarningDialog, SystemRecoveryPanel
from mac_audit_agent.ui.theme_panel import ThemeSettingsPanel
from mac_audit_agent.recovery_center import SystemRecoveryCenter
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer
from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel
from mac_audit_agent.vulnerability_review import AggressiveLocalVulnerabilityReviewer
from mac_audit_agent.themes import DEFAULT_THEME_NAME, theme_for_name, theme_stylesheet


LOGGER = logging.getLogger(__name__)
APP_TITLE = "macOS Security Audit Agent - Liquidsky Network Security"
ABOUT_TITLE = f"About {APP_TITLE}"
USAGE_GUIDE_TITLE = f"How to Use {APP_TITLE}"
RISK_COLORS = {"safe": "#238b45", "sensitive": "#d4a017", "dangerous": "#c0392b"}
SEVERITY_PRIORITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
REVIEW_STATES = ["not reviewed", "reviewed", "needs follow-up", "false positive", "confirmed concern"]
DEFAULT_REMEDIATION_BY_CATEGORY = {
    "network": {
        "steps": [
            "Identify the owning process, listening address, and whether the connection is expected for this Mac.",
            "Preserve the event timeline and command output before blocking, quitting, or changing network settings.",
            "If unexpected, disconnect from untrusted networks and review firewall, proxy, VPN, and sharing settings.",
        ],
        "verification": ["Refresh logs, re-run the scan, and confirm the listener or connection no longer appears unexpectedly."],
    },
    "persistence": {
        "steps": [
            "Inspect the launch item, schedule, owner, signature, and referenced executable before removing anything.",
            "Create or confirm an evidence snapshot so the original plist/script/path can be recovered if needed.",
            "Disable or remove the item only after confirming it is not legitimate management, security, backup, or developer tooling.",
        ],
        "verification": ["Restart or reload the session as appropriate, refresh logs, and confirm the item does not recreate itself."],
    },
    "accounts": {
        "steps": [
            "Confirm whether the account, group membership, login event, or privilege change was authorized.",
            "Preserve login history and related monitor events before changing passwords or removing privileges.",
            "If unauthorized, rotate affected credentials and remove only the unexpected privilege or account after review.",
        ],
        "verification": ["Refresh account logs and re-run the scan to confirm user and admin membership match expectations."],
    },
    "files": {
        "steps": [
            "Review the file path, owner, modification time, quarantine metadata, and whether an expected application created it.",
            "Do not delete evidence until a snapshot or report has been created.",
            "If suspicious, isolate the file by moving it through the app's recovery workflow or manual quarantine process.",
        ],
        "verification": ["Refresh file/process logs and confirm the path is absent or no longer executable from an unsafe location."],
    },
    "process": {
        "steps": [
            "Review process path, parent process, signature, command line, and network activity together.",
            "Preserve process and network evidence before terminating the process.",
            "If malicious or unauthorized, stop it through normal app controls first, then remove the associated persistence path.",
        ],
        "verification": ["Refresh process logs and re-run the scan to confirm the process and related listener are gone."],
    },
    "vulnerability": {
        "steps": [
            "Confirm the detected local product and version match the advisory before remediation.",
            "Use the vendor or Apple-supported update path rather than downloading random installers.",
            "Prioritize known exploited, locally applicable, high-confidence items first.",
        ],
        "verification": ["Refresh the forecast or vulnerability scan and confirm the fixed version is detected locally."],
    },
    "baseline": {
        "steps": [
            "Compare the change against expected maintenance, updates, installs, and administrative activity.",
            "Record whether the change is expected, suspicious, or needs follow-up.",
            "If suspicious, preserve logs and investigate the related process, user, network, and persistence evidence before cleanup.",
        ],
        "verification": ["Refresh baseline comparison after review and confirm expected changes are accepted or unexpected changes are resolved."],
    },
    "monitor": {
        "steps": [
            "Review monitor health, event flow, and recent tamper or blindness events before remediation.",
            "Preserve monitor logs and evidence snapshots before reinstalling or repairing the monitor.",
            "Repair deployment only through the app's monitor repair controls or documented system service process.",
        ],
        "verification": ["Refresh monitor logs and run the event-flow verification to confirm alerts and persistence are working."],
    },
    "default": {
        "steps": [
            "Read the evidence, category, severity, and false-positive notes before taking action.",
            "Create or export an evidence snapshot if the finding may be security relevant.",
            "Apply the least disruptive fix first, then document what changed in the review notes.",
        ],
        "verification": ["Refresh logs, re-run the relevant scan category, and confirm the finding is resolved or correctly marked reviewed."],
    },
}
STARTUP_STRATEGY_QUOTES = [
    {"source": "Sun Tzu", "text": "The supreme art of war is to subdue the enemy without fighting."},
    {"source": "Sun Tzu", "text": "In the midst of chaos, there is also opportunity."},
    {"source": "Sun Tzu", "text": "If you know the enemy and know yourself, you need not fear the result of a hundred battles."},
    {"source": "Sun Tzu", "text": "Victorious warriors win first and then go to war."},
    {"source": "Sun Tzu", "text": "All warfare is based on deception."},
    {"source": "Sun Tzu", "text": "Appear weak when you are strong, and strong when you are weak."},
    {"source": "Sun Tzu", "text": "He will win who knows when to fight and when not to fight."},
    {"source": "Strategy Note", "text": "Power is easier to keep when your intentions are disciplined and your signals are deliberate."},
    {"source": "Strategy Note", "text": "Control the tempo: make evidence, timing, and context work before you act."},
    {"source": "Strategy Note", "text": "Never let attention outrun preparation; visibility without leverage is noise."},
    {"source": "Strategy Note", "text": "Influence starts with attention, but trust is won by restraint and precision."},
    {"source": "Strategy Note", "text": "Create space for others to reveal intent before you reveal your own conclusion."},
    {"source": "Strategy Note", "text": "Mastery comes from patient repetition, clear feedback, and ruthless correction of weak habits."},
    {"source": "Strategy Note", "text": "Study the system until anomalies stand out without drama."},
    {"source": "Strategy Note", "text": "Skill compounds when every investigation leaves better notes, cleaner tools, and sharper judgment."},
]


def format_startup_strategy_quote(entry: dict[str, str]) -> str:
    return f"{entry['source']}: {entry['text']}"


def choose_startup_strategy_quote(previous_quote: str = "", rng: random.Random | None = None) -> str:
    chooser = rng or random.SystemRandom()
    formatted = [format_startup_strategy_quote(entry) for entry in STARTUP_STRATEGY_QUOTES]
    candidates = [quote for quote in formatted if quote != previous_quote]
    return chooser.choice(candidates or formatted)


class ClickableLabel(QLabel):
    clicked = Signal()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class PacketCaptureOptionsDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Packet Capture Snapshot")
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Interface"))
        self.interface_combo = QComboBox()
        for name in list_capture_interfaces():
            self.interface_combo.addItem(name)
        layout.addWidget(self.interface_combo)

        layout.addWidget(QLabel("Duration"))
        self.duration_combo = QComboBox()
        self.duration_combo.addItem("30 seconds", 30)
        self.duration_combo.addItem("60 seconds", 60)
        self.duration_combo.addItem("5 minutes", 300)
        self.duration_combo.addItem("Custom", "custom")
        layout.addWidget(self.duration_combo)
        self.custom_duration_input = QLineEdit()
        self.custom_duration_input.setPlaceholderText("Custom duration in seconds (max 600)")
        layout.addWidget(self.custom_duration_input)

        layout.addWidget(QLabel("Filter"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("None", "")
        self.filter_combo.addItem("host 127.0.0.1", "host 127.0.0.1")
        self.filter_combo.addItem("tcp", "tcp")
        self.filter_combo.addItem("udp", "udp")
        self.filter_combo.addItem("port", "port")
        layout.addWidget(self.filter_combo)
        self.port_filter_input = QLineEdit()
        self.port_filter_input.setPlaceholderText("Port number")
        layout.addWidget(self.port_filter_input)

        self.output_label = QLabel(f"Output folder: {default_evidence_dir()}")
        self.output_label.setWordWrap(True)
        layout.addWidget(self.output_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> dict[str, object]:
        duration_value = self.duration_combo.currentData()
        if duration_value == "custom":
            duration = validate_capture_duration(int(self.custom_duration_input.text().strip()))
        else:
            duration = validate_capture_duration(int(duration_value))
        filter_value = str(self.filter_combo.currentData())
        if filter_value == "port":
            filter_value = f"port {self.port_filter_input.text().strip()}"
        return {
            "interface": sanitize_interface_name(self.interface_combo.currentText()),
            "duration_seconds": duration,
            "capture_filter": sanitize_capture_filter(filter_value),
            "output_dir": default_evidence_dir(),
        }


class PacketCaptureConfirmDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Packet Capture Warning")
        layout = QVBoxLayout(self)
        warning = QLabel(
            "Packet captures may contain sensitive traffic metadata or contents. Use this only on systems and networks you are authorized to monitor. "
            "Captures are stored locally and are not uploaded. The capture will stop automatically after the selected duration."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.acknowledge = QCheckBox("I understand")
        layout.addWidget(self.acknowledge)
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Type CAPTURE")
        layout.addWidget(self.confirm_input)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self) -> None:
        if not self.acknowledge.isChecked() or self.confirm_input.text().strip() != "CAPTURE":
            QMessageBox.warning(self, "Confirmation Required", "Check 'I understand' and type CAPTURE to proceed.")
            return
        super().accept()


class PacketCaptureProgressDialog(QDialog):
    def __init__(self, session: PacketCaptureSession, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.session = session
        self.result = None
        self.setWindowTitle("Packet Capture Running")
        layout = QVBoxLayout(self)
        self.status_label = QLabel("Status: waiting")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.countdown_label = QLabel(f"Time remaining: {self.session.duration_seconds}s")
        layout.addWidget(self.countdown_label)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_capture)
        layout.addWidget(self.cancel_button)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

    def start_capture(self) -> None:
        try:
            self.session.start()
        except Exception as exc:
            self.status_label.setText(f"Status: failed\n{exc}")
            self.result = self.session._result_from_state()
            self.result.metadata["status"] = "failed"
            self.result.metadata["stderr_summary"] = str(exc)
            self.reject()
            return
        self.status_label.setText("Status: running")
        self.timer.start(250)

    def _tick(self) -> None:
        remaining = self.session.seconds_remaining()
        self.countdown_label.setText(f"Time remaining: {remaining}s")
        if remaining <= 0:
            self.timer.stop()
            self.result = self.session.finish()
            self.status_label.setText(f"Status: {self.result.metadata.get('status', 'completed')}")
            self.accept()

    def cancel_capture(self) -> None:
        self.timer.stop()
        self.result = self.session.cancel()
        self.status_label.setText("Status: cancelled")
        self.reject()


class LongActionWorker(QObject):
    progress = Signal(dict)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, action: Callable[[Callable[[dict], None]], object]) -> None:
        super().__init__()
        self.action = action

    def run(self) -> None:
        try:
            self.completed.emit(self.action(lambda payload: self.progress.emit(dict(payload))))
        except Exception as exc:
            self.failed.emit(str(exc))


class GuidedLongActionDialog(QDialog):
    def __init__(self, title: str, phases: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.result_data: object = None
        self.error = ""
        self._phases = phases or ["Working in the background."]
        self._phase_index = 0
        self.worker_thread: QThread | None = None
        self.worker: LongActionWorker | None = None
        layout = QVBoxLayout(self)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: 700;")
        layout.addWidget(title_label)
        self.status_label = QLabel(self._phases[0])
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.detail_label = QLabel("The app is keeping this work off the main interface so it can continue responding.")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, max(1, len(self._phases)))
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        self.close_button = QPushButton("Running...")
        self.close_button.setEnabled(False)
        layout.addWidget(self.close_button)
        self.timer = QTimer(self)
        self.timer.setInterval(1200)
        self.timer.timeout.connect(self._advance_phase)

    def start_action(self, action: Callable[[Callable[[dict], None]], object]) -> None:
        self.worker_thread = QThread(self)
        self.worker = LongActionWorker(action)
        self.worker.moveToThread(self.worker_thread)
        self.worker.progress.connect(self._update_progress)
        self.worker.completed.connect(self._complete)
        self.worker.failed.connect(self._fail)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.completed.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.timer.start()
        self.worker_thread.start()

    def _advance_phase(self) -> None:
        self._phase_index = min(self._phase_index + 1, len(self._phases) - 1)
        self.status_label.setText(self._phases[self._phase_index])
        self.progress_bar.setValue(self._phase_index)

    def _update_progress(self, payload: dict) -> None:
        message = str(payload.get("message", "")).strip()
        if message:
            self.status_label.setText(message)
        completed = payload.get("completed")
        total = payload.get("total")
        if completed is not None and total is not None:
            maximum = max(1, int(total))
            self.progress_bar.setRange(0, maximum)
            self.progress_bar.setValue(min(int(completed), maximum))

    def _complete(self, result: object) -> None:
        self.timer.stop()
        self.result_data = result
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.status_label.setText("Completed. Preparing results for display.")
        self.accept()

    def _fail(self, error: str) -> None:
        self.timer.stop()
        self.error = error
        self.status_label.setText(f"Failed: {error}")
        super().reject()

    def reject(self) -> None:
        if self.worker_thread is not None and self.worker_thread.isRunning():
            self.status_label.setText("This action is still finishing. Please wait.")
            return
        super().reject()


class NetworkDiscoveryOptionsDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Network Discovery")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Interface"))
        self.interface_combo = QComboBox()
        for name in list_network_interfaces():
            self.interface_combo.addItem(name)
        preferred_interface = detect_preferred_interface()
        preferred_index = self.interface_combo.findText(preferred_interface)
        if preferred_index >= 0:
            self.interface_combo.setCurrentIndex(preferred_index)
        self.interface_combo.currentIndexChanged.connect(self._refresh_scope)
        layout.addWidget(self.interface_combo)
        layout.addWidget(QLabel("Scan Mode"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Quick Discovery", "quick")
        self.profile_combo.addItem("Standard Discovery", "standard")
        self.profile_combo.addItem("Deep Discovery", "deep")
        self.profile_combo.currentIndexChanged.connect(self._refresh_scope)
        layout.addWidget(self.profile_combo)
        self.profile_label = QLabel("")
        self.profile_label.setWordWrap(True)
        layout.addWidget(self.profile_label)
        self.scope_label = QLabel("")
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        self.public_confirm = QCheckBox("I confirm this public or non-RFC1918 range is my local network")
        self.public_confirm.setVisible(False)
        layout.addWidget(self.public_confirm)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._refresh_scope()

    def _refresh_scope(self, *_args) -> None:
        try:
            scope = detect_network_scope(self.interface_combo.currentText())
            subnet = scope.get("subnet", "")
            scope_text = (
                f"Detected subnet: {subnet}\n"
                f"Gateway: {scope.get('gateway', '')}\n"
                f"Broadcast: {scope.get('broadcast', '')}\n"
                f"Scope: {scope.get('scope', '')}"
            )
            self.scope_label.setText(scope_text)
            self.public_confirm.setVisible(scope.get("scope") != "private")
            profile_name = str(self.profile_combo.currentData() or "standard")
            profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["standard"])
            ping_limit = int(profile.get("ping_limit", 0))
            use_mdns = bool(profile.get("use_mdns", False))
            retries = int(profile.get("ping_retries", 1))
            workers = int(profile.get("max_workers", 0))
            details = [
                f"Threads: {workers}",
                f"Pipeline: ARP first -> mDNS/Bonjour -> {'threaded ping fallback' if ping_limit else 'no active ping'} -> enrichment -> baseline comparison",
                f"Ping targets: {'ARP + mDNS only' if ping_limit == 0 else f'up to {ping_limit} hosts'}",
                f"mDNS: {'enabled' if use_mdns else 'disabled'}",
                f"Retries: {retries}",
            ]
            self.profile_label.setText(" | ".join(details))
        except Exception as exc:
            self.scope_label.setText(f"Unable to detect subnet: {exc}")
            self.public_confirm.setVisible(False)
            self.profile_label.setText("")

    def values(self) -> dict[str, object]:
        interface = sanitize_network_interface_name(self.interface_combo.currentText())
        scope = detect_network_scope(interface)
        return {
            "interface": interface,
            "scan_profile": str(self.profile_combo.currentData() or "standard"),
            "subnet": scope.get("subnet", ""),
            "scope": scope.get("scope", ""),
            "gateway": scope.get("gateway", ""),
            "confirm_public": self.public_confirm.isChecked(),
        }

    def accept(self) -> None:
        try:
            scope = detect_network_scope(self.interface_combo.currentText())
        except Exception as exc:
            QMessageBox.warning(self, "Network Discovery", str(exc))
            return
        if scope.get("scope") != "private" and not self.public_confirm.isChecked():
            QMessageBox.warning(self, "Network Discovery", "Public or non-RFC1918 ranges require explicit confirmation that this is your local network.")
            return
        super().accept()


class NetworkDiscoveryConfirmDialog(QDialog):
    def __init__(self, subnet: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Network Discovery")
        layout = QVBoxLayout(self)
        warning = QLabel(
            "Only scan networks you own or are authorized to assess.\n\n"
            "This scan identifies devices visible on your local network. A new or unknown device is not proof of compromise, but it may be worth investigating if you do not recognize it.\n\n"
            f"Selected subnet: {subnet}"
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.acknowledge = QCheckBox("I understand")
        layout.addWidget(self.acknowledge)
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Type DISCOVER")
        layout.addWidget(self.confirm_input)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self) -> None:
        if not self.acknowledge.isChecked() or self.confirm_input.text().strip() != "DISCOVER":
            QMessageBox.warning(self, "Confirmation Required", "Check 'I understand' and type DISCOVER to proceed.")
            return
        super().accept()


class NetworkDiscoveryWorker(QObject):
    discovery_progress = Signal(dict)
    discovery_completed = Signal(object)
    discovery_failed = Signal(str)
    finished = Signal()

    def __init__(self, collector, options: dict[str, object], previous: dict | None) -> None:
        super().__init__()
        self.collector = collector
        self.options = options
        self.previous = previous or {}
        self._cancel_requested = False

    def request_cancel(self) -> None:
        self._cancel_requested = True

    def _cancel_check(self) -> bool:
        current_thread = QThread.currentThread()
        return self._cancel_requested or current_thread.isInterruptionRequested()

    def run(self) -> None:
        try:
            previous_hosts_data = self.previous.get("hosts", [])
            previous_hosts = [NetworkHostSnapshot(**item) if isinstance(item, dict) else item for item in previous_hosts_data]
            result = self.collector.collect_network_discovery(
                interface=str(self.options["interface"]),
                scan_profile=str(self.options.get("scan_profile", "standard")),
                confirm_public_network=bool(self.options.get("confirm_public", False)),
                progress_callback=lambda payload: self.discovery_progress.emit(dict(payload)),
                cancel_check=self._cancel_check,
                previous_hosts=previous_hosts,
                previous_gateway=str(self.previous.get("gateway", "")),
                previous_gateway_mac=str(self.previous.get("gateway_mac", "")),
                previous_subnet=str(self.previous.get("subnet", "")),
            )
        except Exception as exc:  # pragma: no cover - defensive, surfaced via signal
            self.discovery_failed.emit(str(exc))
        else:
            self.discovery_completed.emit(result)
        finally:
            self.finished.emit()


class NetworkDiscoveryProgressDialog(QDialog):
    def __init__(self, collector, options: dict[str, object], previous: dict | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.collector = collector
        self.options = options
        self.previous = previous or {}
        self.progress_state = {"stage": "starting", "completed": 0, "total": 1, "message": "Preparing network discovery."}
        self.result_data = None
        self.error: str | None = None
        self._finished = False
        self.worker_thread: QThread | None = None
        self.worker: NetworkDiscoveryWorker | None = None
        self.setWindowTitle("Network Discovery Running")
        layout = QVBoxLayout(self)
        self.status_label = QLabel("Preparing network discovery.")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        layout.addWidget(self.cancel_button)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

    def _update_progress(self, payload: dict[str, object]) -> None:
        self.progress_state = dict(payload)

    def _finalize_success(self) -> None:
        if self._finished:
            return
        self._finished = True
        self.timer.stop()
        self._stop_worker()
        self.accept()

    def _finalize_failure(self) -> None:
        if self._finished:
            return
        self._finished = True
        self.timer.stop()
        self._stop_worker()
        self.reject()

    def start_scan(self) -> None:
        self.worker_thread = QThread(self)
        self.worker = NetworkDiscoveryWorker(self.collector, self.options, self.previous)
        self.worker.moveToThread(self.worker_thread)
        self.worker.discovery_progress.connect(self._update_progress)
        self.worker.discovery_completed.connect(self._on_completed)
        self.worker.discovery_failed.connect(self._on_failed)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()
        self.timer.start(100)

    def _stop_worker(self, timeout_ms: int = 2000) -> None:
        if self.worker is not None:
            self.worker.request_cancel()
        if self.worker_thread is not None:
            self.worker_thread.requestInterruption()
            self.worker_thread.quit()
            self.worker_thread.wait(timeout_ms)

    def _on_completed(self, result) -> None:
        self.result_data = result
        self.error = None
        self._finalize_success()

    def _on_failed(self, error_text: str) -> None:
        self.error = error_text
        self._finalize_failure()

    def _tick(self) -> None:
        completed = int(self.progress_state.get("completed", 0))
        total = max(1, int(self.progress_state.get("total", 1)))
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(min(completed, total))
        self.status_label.setText(str(self.progress_state.get("message", "Running network discovery.")))
        if self.worker_thread is not None and self.worker_thread.isRunning():
            return
        if self.result_data is not None:
            self._finalize_success()
        elif self.error is not None:
            self._finalize_failure()

    def cancel_scan(self) -> None:
        self._stop_worker()
        self.cancel_button.setEnabled(False)
        self.status_label.setText("Cancelling network discovery.")

    def closeEvent(self, event) -> None:
        self.cancel_scan()
        super().closeEvent(event)


def severity_qcolors(severity: str) -> tuple[QColor, QColor]:
    colors = SEVERITY_COLOR_MAP[severity]
    return QColor(colors["bg"]), QColor(colors["fg"])


def finding_to_dict(finding):
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    if hasattr(finding, "__dict__"):
        return dict(finding.__dict__)
    return {}


def normalize_finding(finding):
    return finding_to_dict(finding)


def normalize_findings(findings):
    return [normalize_finding(finding) for finding in (findings or [])]


def finding_duplicate_group_key(finding: dict) -> str:
    return "|".join(
        [
            str(finding.get("category", "")),
            str(finding.get("title", "")),
            str(finding.get("severity", "info")),
            str(finding.get("rule_id", "")),
            str(finding.get("event_type", "")),
            str(finding.get("command_used", "")),
            str(finding.get("evidence_summary", finding.get("evidence", ""))),
        ]
    )


def duplicate_category_for_count(count: int) -> str:
    if count <= 1:
        return "single"
    if count < 10:
        return "duplicate_burst"
    return "high_volume_duplicate"


def deduplicate_findings_for_display(findings: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    order: list[str] = []
    for finding in findings:
        item = dict(finding)
        key = finding_duplicate_group_key(item)
        if key not in grouped:
            item["occurrence_count"] = 1
            item["duplicate_count"] = 0
            item["duplicate_category"] = "single"
            item["duplicate_group_key"] = key
            item["duplicate_ids"] = [str(item.get("id", ""))]
            grouped[key] = item
            order.append(key)
            continue
        representative = grouped[key]
        occurrence_count = int(representative.get("occurrence_count", 1) or 1) + 1
        representative["occurrence_count"] = occurrence_count
        representative["duplicate_count"] = occurrence_count - 1
        representative["duplicate_category"] = duplicate_category_for_count(occurrence_count)
        duplicate_ids = list(representative.get("duplicate_ids", []))
        duplicate_ids.append(str(item.get("id", "")))
        representative["duplicate_ids"] = duplicate_ids
    return [grouped[key] for key in order]


def create_security_tray_icon(size: int = 64) -> QIcon:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    shield = QPainterPath()
    shield.moveTo(size * 0.50, size * 0.08)
    shield.lineTo(size * 0.82, size * 0.20)
    shield.cubicTo(size * 0.80, size * 0.58, size * 0.69, size * 0.79, size * 0.50, size * 0.92)
    shield.cubicTo(size * 0.31, size * 0.79, size * 0.20, size * 0.58, size * 0.18, size * 0.20)
    shield.closeSubpath()
    painter.setBrush(QBrush(QColor("#0B1220")))
    painter.setPen(QPen(QColor("#7DD3FC"), max(2, size // 24)))
    painter.drawPath(shield)

    inner = QPainterPath()
    inner.moveTo(size * 0.50, size * 0.18)
    inner.lineTo(size * 0.72, size * 0.27)
    inner.cubicTo(size * 0.69, size * 0.55, size * 0.62, size * 0.70, size * 0.50, size * 0.80)
    inner.cubicTo(size * 0.38, size * 0.70, size * 0.31, size * 0.55, size * 0.28, size * 0.27)
    inner.closeSubpath()
    painter.setBrush(QBrush(QColor("#0EA5E9")))
    painter.setPen(Qt.NoPen)
    painter.drawPath(inner)

    lock_body = QRectF(size * 0.35, size * 0.46, size * 0.30, size * 0.22)
    painter.setBrush(QBrush(QColor("#F8FAFC")))
    painter.drawRoundedRect(lock_body, size * 0.04, size * 0.04)
    painter.setPen(QPen(QColor("#F8FAFC"), max(3, size // 16)))
    painter.drawArc(QRectF(size * 0.38, size * 0.31, size * 0.24, size * 0.27), 0, 180 * 16)
    painter.setPen(QPen(QColor("#0B1220"), max(2, size // 26)))
    painter.drawLine(QPointF(size * 0.50, size * 0.54), QPointF(size * 0.50, size * 0.61))
    painter.end()

    return QIcon(pixmap)


class MainWindow(QMainWindow):
    def __init__(self, db_path: Path, config: AuditConfig | None = None) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1440, 900)
        self.security_icon = create_security_tray_icon()
        self.setWindowIcon(self.security_icon)

        self.db_path = db_path
        self.config = config or AuditConfig()
        self.registry = build_command_registry()
        self.runner = SafeCommandRunner(RunnerConfig(dry_run=self.config.dry_run))
        self.collectors = CollectorSuite(self.runner, self.config)
        self.db = AuditDatabase(db_path, self.config.logs_dir, self.config.log_retention_days)
        self.startup_quote = self._select_startup_quote()
        self.notification_manager = NotificationManager(self.db)
        self.cve_radar_engine = CveRadarEngine(self.db, self.config)
        self.recovery_center = SystemRecoveryCenter(self.db, self.config)
        self.workflow_layer = InvestigatorWorkflowLayer(self.db)
        self.intrusion_correlation_engine = IntrusionCorrelationEngine(self.db, self.workflow_layer)
        self.execution_evidence_engine = ExecutionEvidenceEngine()
        self.investigation_priority_engine = InvestigationPriorityEngine(self.db, self.workflow_layer)
        self.family_safety_auditor = FamilySafetyAuditor()
        self.launch_agent_manager = LaunchAgentManager(db_path)
        self.vulnerability_reviewer = AggressiveLocalVulnerabilityReviewer(self.config)
        self.current_scan_summary: ScanSummary | None = None
        self.current_payload: dict | None = None
        self.current_visible_findings: list[dict] = []
        self.current_selected_finding: dict | None = None
        self.family_safety_report = None
        self.execution_evidence_findings: list[dict] = []
        self.operational_health_engine = OperationalHealthEngine(
            self.db,
            user_launch_agent=self.launch_agent_manager,
            system_launch_agent=LaunchAgentManager(self.db_path, scope="system"),
            notification_manager=self.notification_manager,
            system_readiness=SystemMonitorReadiness(default_monitor_db_path("system")),
            cve_radar_engine=self.cve_radar_engine,
        )
        self._active_network_discovery_dialog: NetworkDiscoveryProgressDialog | None = None
        self.tray_icon: QSystemTrayIcon | None = None
        self.tray_status_action: QAction | None = None
        self.tray_events_action: QAction | None = None
        self.tray_status_timer: QTimer | None = None
        self._force_quit_from_tray = False
        self.findings_sort_order = "critical_to_low"
        self.last_ui_debug: dict[str, object] = {}
        try:
            self.current_scan_result = self.db.latest_scan_result()
        except Exception as exc:
            LOGGER.exception("Failed to load latest scan result at startup: %s", exc)
            self.current_scan_result = None
        self.current_scan_active = self.current_scan_result is not None

        self._build_ui()
        self._build_menus()
        self._set_developer_mode(self._developer_mode_enabled(), persist=False)
        self._setup_tray_icon()
        self._load_registry()
        self._refresh_command_preview_page()
        self._refresh_dashboard()
        self.refresh_operational_health()
        self.apply_theme_choice(
            self.db.get_background_monitor_state("selected_theme", DEFAULT_THEME_NAME),
            self.db.get_background_monitor_state("accessibility_high_contrast", "0") == "1",
        )
        if self.current_scan_result is not None:
            self._load_scan_result(self.current_scan_result)
        else:
            self.summary_label.setText("No active scan. Run a scan to begin.")
            self.refresh_intrusion_detection()
            self.refresh_flight_recorder()
            self.refresh_logs_page()
        self.refresh_apple_security_forecast(manual=False, initial_load=True)
        self.refresh_system_recovery(manual=False, initial_load=True)

    def _select_startup_quote(self) -> str:
        previous_quote = self.db.get_background_monitor_state("startup_strategy_quote", "")
        quote = choose_startup_strategy_quote(previous_quote)
        self.db.set_background_monitor_state("startup_strategy_quote", quote)
        return quote

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(8)

        self.sidebar = QListWidget()
        self.sidebar.addItems([
            "Dashboard",
            "Family & Safety",
            "Intrusion Detection",
            "Investigation Priorities",
            "Flight Recorder",
            "Evidence Snapshots",
            "Logs",
            "Settings",
            "Skins",
            "Scan Categories",
            "Results",
            "Investigation Notes",
            "Command Preview",
        ])
        self.sidebar.setMaximumWidth(240)
        self.sidebar.setMinimumWidth(150)
        self.sidebar.currentRowChanged.connect(self._change_page)

        self.cve_radar_panel = CveRadarPanel(self)
        self.cve_radar_panel.update_requested.connect(lambda: self.refresh_apple_security_forecast(manual=True))
        self.cve_radar_panel.diagnostics_requested.connect(self.show_apple_security_forecast_diagnostics)
        self.cve_radar_panel.export_requested.connect(self.export_html)
        self.cve_radar_panel.review_requested.connect(self._review_cve_radar_card)
        self.cve_radar_panel.snooze_requested.connect(self._snooze_cve_radar_card)
        self.cve_radar_panel.set_status("Forecast not checked yet")
        self.family_safety_panel = FamilySafetyPanel(self)
        self.family_safety_panel.audit_requested.connect(self.run_family_safety_audit)
        self.family_safety_panel.export_html_requested.connect(self.export_family_safety_html)
        self.family_safety_panel.export_json_requested.connect(self.export_family_safety_json)
        self.intrusion_detection_panel = IntrusionDetectionPanel()
        self.intrusion_detection_panel.refresh_requested.connect(self.refresh_intrusion_detection)
        self.intrusion_detection_panel.show_context_requested.connect(self._show_intrusion_context)
        self.intrusion_detection_panel.snapshot_requested.connect(self.create_system_recovery_snapshot)
        self.intrusion_detection_panel.export_ai_summary_requested.connect(self.export_intrusion_ai_summary)
        self.intrusion_detection_panel.open_logs_requested.connect(self.show_logs_page)
        self.flight_recorder_panel = FlightRecorderPanel("Flight Recorder", "Timeline of surrounding activity and correlated patterns.")
        self.flight_recorder_panel.refresh_requested.connect(self.refresh_flight_recorder)
        self.flight_recorder_panel.show_context_requested.connect(self._show_intrusion_context)
        self.flight_recorder_panel.snapshot_requested.connect(self.create_system_recovery_snapshot)
        self.flight_recorder_panel.export_ai_summary_requested.connect(self.export_intrusion_ai_summary)
        self.flight_recorder_panel.open_logs_requested.connect(self.show_logs_page)
        self.investigation_priority_nav_panel = InvestigationPriorityPanel()
        self.logs_panel = LogsPanel(self)
        self.logs_panel.refresh_requested.connect(self.refresh_logs_page)
        self.logs_panel.clear_requested.connect(self.clear_logs_category)
        self.logs_panel.open_reports_requested.connect(self.open_reports_folder)
        self.theme_panel = ThemeSettingsPanel(self)
        self.theme_panel.theme_changed.connect(self.apply_theme_choice)
        self.operational_health_panel = OperationalHealthPanel(self)
        self.operational_health_panel.refresh_requested.connect(self.refresh_operational_health)
        self.background_monitor_panel = BackgroundMonitorPanel(self.db, self.launch_agent_manager, self)
        self.operational_health_panel.audit_deployment_requested.connect(self.background_monitor_panel.audit_system_monitor_deployment)
        self.operational_health_panel.verify_event_flow_requested.connect(self.background_monitor_panel.verify_system_monitor_event_flow)
        self.system_recovery_panel = SystemRecoveryPanel(self)
        self.system_recovery_panel.incident_check_requested.connect(self.run_system_recovery_incident_check)
        self.system_recovery_panel.snapshot_requested.connect(self.create_system_recovery_snapshot)
        self.system_recovery_panel.preview_requested.connect(self.preview_system_recovery_cleanup)
        self.system_recovery_panel.cleanup_requested.connect(self.run_system_recovery_cleanup)
        self.system_recovery_panel.open_snapshots_requested.connect(self.open_system_recovery_snapshots_folder)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_dashboard_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_family_safety_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_intrusion_detection_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_investigation_priorities_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_flight_recorder_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_system_recovery_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_logs_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_settings_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_skins_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_categories_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_results_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_investigation_notes_page(), resizable=True))
        self.pages.addWidget(self._wrap_in_scroll_area(self._build_preview_page(), resizable=True))
        self.sidebar.setCurrentRow(0)

        self.details_panel = self._build_selected_command_panel()
        self.main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.addWidget(self.pages)
        self.main_splitter.addWidget(self.details_panel)
        self.main_splitter.setSizes([1000, 360])

        outer.addWidget(self.sidebar)
        outer.addWidget(self.main_splitter)
        self._update_responsive_layout()
        self.cve_radar_timer = QTimer(self)
        self.cve_radar_timer.setInterval(self.cve_radar_engine.update_interval_seconds * 1000)
        self.cve_radar_timer.timeout.connect(self.refresh_apple_security_forecast)
        self.cve_radar_timer.start()

    def _wrap_in_scroll_area(self, widget: QWidget, *, resizable: bool) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(resizable)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(widget)
        return scroll

    def _developer_mode_enabled(self) -> bool:
        stored = self.db.get_background_monitor_state("developer_mode", "")
        if stored:
            return stored == "1"
        return bool(getattr(self.config, "developer_mode", False))

    def _set_developer_mode(self, enabled: bool, *, persist: bool) -> None:
        self.config.developer_mode = enabled
        if persist:
            self.db.set_background_monitor_state("developer_mode", "1" if enabled else "0")
        if hasattr(self, "developer_mode_action"):
            self.developer_mode_action.blockSignals(True)
            self.developer_mode_action.setChecked(enabled)
            self.developer_mode_action.blockSignals(False)
        for action in getattr(self, "developer_monitor_actions", []):
            action.setVisible(enabled)
            action.setToolTip(
                "Developer Mode only: creates synthetic monitor/notifier events."
                if enabled
                else "Hidden unless Settings > Developer Mode is enabled."
            )
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.set_developer_mode(enabled)
        if hasattr(self, "operational_health_panel") and hasattr(self.operational_health_panel, "set_developer_mode"):
            self.operational_health_panel.set_developer_mode(enabled)

    def _build_dashboard_action_group(self, title: str, widgets: list[QWidget]) -> QFrame:
        frame = QFrame()
        frame.setProperty("themeCard", True)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: 700; color: #D6E4FF;")
        layout.addWidget(title_label)
        for widget in widgets:
            layout.addWidget(widget)
        return frame

    def _build_menus(self) -> None:
        diagnostics_menu = self.menuBar().addMenu("Diagnostics")
        action = QAction("Show Last Collector Debug", self)
        action.triggered.connect(self.show_last_collector_debug)
        diagnostics_menu.addAction(action)
        vulnerability_review_action = QAction("Aggressive Local Vulnerability Review", self)
        vulnerability_review_action.triggered.connect(self.run_aggressive_local_vulnerability_review)
        diagnostics_menu.addAction(vulnerability_review_action)
        full_localhost_scan_action = QAction("Full Localhost Port Scan", self)
        full_localhost_scan_action.triggered.connect(self.run_full_localhost_port_scan)
        diagnostics_menu.addAction(full_localhost_scan_action)
        advanced_evidence_menu = self.menuBar().addMenu("Advanced Evidence")
        packet_capture_action = QAction("Packet Capture Snapshot", self)
        packet_capture_action.triggered.connect(self.run_packet_capture_snapshot)
        advanced_evidence_menu.addAction(packet_capture_action)
        network_discovery_action = QAction("Local Network Device Discovery", self)
        network_discovery_action.triggered.connect(self.run_network_discovery)
        advanced_evidence_menu.addAction(network_discovery_action)
        background_monitor_menu = self.menuBar().addMenu("Background Monitor")
        self.developer_monitor_actions: list[QAction] = []
        generate_test_event_action = QAction("Developer: Generate Test Event", self)
        generate_test_event_action.triggered.connect(self.trigger_background_monitor_test_event)
        background_monitor_menu.addAction(generate_test_event_action)
        self.developer_monitor_actions.append(generate_test_event_action)
        test_notification_action = QAction("Developer: Test Notification", self)
        test_notification_action.triggered.connect(self.trigger_background_monitor_test_notification)
        background_monitor_menu.addAction(test_notification_action)
        self.developer_monitor_actions.append(test_notification_action)
        test_dialog_action = QAction("Developer: Test High Priority Dialog", self)
        test_dialog_action.triggered.connect(self.trigger_background_monitor_test_dialog)
        background_monitor_menu.addAction(test_dialog_action)
        self.developer_monitor_actions.append(test_dialog_action)
        test_overlay_action = QAction("Developer: Test Bottom-Right Alert", self)
        test_overlay_action.triggered.connect(self.trigger_background_monitor_test_overlay)
        background_monitor_menu.addAction(test_overlay_action)
        self.developer_monitor_actions.append(test_overlay_action)
        test_idle_warning_action = QAction("Developer: Test Idle Activity Warning", self)
        test_idle_warning_action.triggered.connect(self.trigger_background_monitor_test_idle_warning)
        background_monitor_menu.addAction(test_idle_warning_action)
        self.developer_monitor_actions.append(test_idle_warning_action)
        settings_menu = self.menuBar().addMenu("Settings")
        family_safety_action = QAction("Family & Safety", self)
        family_safety_action.triggered.connect(self.show_family_safety_page)
        settings_menu.addAction(family_safety_action)
        appearance_action = QAction("Appearance", self)
        appearance_action.triggered.connect(self.show_skins_page)
        settings_menu.addAction(appearance_action)
        event_priorities_action = QAction("Event Priorities", self)
        event_priorities_action.triggered.connect(lambda: self.background_monitor_panel.show_event_priorities_dialog())
        settings_menu.addAction(event_priorities_action)
        monitor_protection_action = QAction("Monitor Protection", self)
        monitor_protection_action.triggered.connect(lambda: self.background_monitor_panel.show_monitor_protection_dialog())
        settings_menu.addAction(monitor_protection_action)
        monitor_mode_action = QAction("Monitor Mode", self)
        monitor_mode_action.triggered.connect(lambda: self.background_monitor_panel.show_monitor_mode_dialog())
        settings_menu.addAction(monitor_mode_action)
        self.developer_mode_action = QAction("Developer Mode", self)
        self.developer_mode_action.setCheckable(True)
        self.developer_mode_action.setToolTip("Show synthetic monitor test controls. Disabled by default.")
        self.developer_mode_action.toggled.connect(lambda enabled: self._set_developer_mode(enabled, persist=True))
        settings_menu.addAction(self.developer_mode_action)
        help_menu = self.menuBar().addMenu("Help")
        about_action = QAction("About Mac Audit Agent", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    def _setup_tray_icon(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            LOGGER.info("System tray is not available; tray monitor icon disabled.")
            return
        app = QApplication.instance()
        if app is not None:
            app.setQuitOnLastWindowClosed(False)

        self.tray_icon = QSystemTrayIcon(self.security_icon, self)
        self.tray_icon.setToolTip(APP_TITLE)
        self.tray_icon.activated.connect(self._handle_tray_activation)

        tray_menu = QMenu(self)
        open_action = QAction("Open Security Viewer", self)
        open_action.triggered.connect(self.restore_from_tray)
        tray_menu.addAction(open_action)

        settings_action = QAction("Background Monitor", self)
        settings_action.triggered.connect(self.open_background_monitor_from_tray)
        tray_menu.addAction(settings_action)

        logs_action = QAction("View Security Logs", self)
        logs_action.triggered.connect(self.open_logs_from_tray)
        tray_menu.addAction(logs_action)

        tray_menu.addSeparator()
        self.tray_status_action = QAction("Monitor status: checking", self)
        self.tray_status_action.setEnabled(False)
        tray_menu.addAction(self.tray_status_action)
        self.tray_events_action = QAction("Recent events: checking", self)
        self.tray_events_action.setEnabled(False)
        tray_menu.addAction(self.tray_events_action)

        refresh_action = QAction("Refresh Status", self)
        refresh_action.triggered.connect(self._refresh_tray_status)
        tray_menu.addAction(refresh_action)

        tray_menu.addSeparator()
        quit_action = QAction("Quit Viewer", self)
        quit_action.triggered.connect(self.quit_from_tray)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        self.tray_status_timer = QTimer(self)
        self.tray_status_timer.setInterval(30_000)
        self.tray_status_timer.timeout.connect(self._refresh_tray_status)
        self.tray_status_timer.start()
        self._refresh_tray_status()

    def _tray_monitor_summary(self) -> tuple[str, str]:
        status = self.db.get_background_monitor_status()
        if status.running:
            state = "running"
        elif status.loaded:
            state = "loaded"
        elif status.installed:
            state = "installed, not running"
        else:
            state = "not installed"
        heartbeat = status.last_heartbeat or "no heartbeat recorded"
        details = [
            APP_TITLE,
            f"Background monitor: {state}",
            f"Last heartbeat: {heartbeat}",
            f"Events in last 10 min: {status.events_last_10_minutes}",
        ]
        if status.last_error:
            details.append("Last error recorded")
        return state, "\n".join(details)

    def _refresh_tray_status(self) -> None:
        if self.tray_icon is None:
            return
        state, tooltip = self._tray_monitor_summary()
        status = self.db.get_background_monitor_status()
        self.tray_icon.setToolTip(tooltip)
        if self.tray_status_action is not None:
            self.tray_status_action.setText(f"Monitor status: {state}")
        if self.tray_events_action is not None:
            self.tray_events_action.setText(f"Recent events: {status.events_last_10_minutes} in 10 min")

    def _handle_tray_activation(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in {QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick}:
            self.restore_from_tray()

    def restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self._refresh_tray_status()

    def open_background_monitor_from_tray(self) -> None:
        self.restore_from_tray()
        self.show_background_monitor_page()

    def open_logs_from_tray(self) -> None:
        self.restore_from_tray()
        self.show_logs_page()

    def quit_from_tray(self) -> None:
        self._force_quit_from_tray = True
        app = QApplication.instance()
        if app is not None:
            app.setQuitOnLastWindowClosed(True)
        if self.tray_icon is not None:
            self.tray_icon.hide()
        self.close()

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        header = QFrame()
        self.dashboard_header_layout = QGridLayout(header)
        self.dashboard_header_layout.setContentsMargins(0, 0, 0, 0)
        self.dashboard_header_layout.setHorizontalSpacing(8)
        self.dashboard_header_layout.setVerticalSpacing(8)
        self.score_label = QLabel("Security Score: --")
        self.score_label.setToolTip("Higher is better. This score is based on findings severity, not proof of compromise.")
        self.score_label.setWordWrap(True)
        self.summary_label = QLabel("No scans yet.")
        self.summary_label.setWordWrap(True)
        self.startup_quote_label = QLabel(self.startup_quote)
        self.startup_quote_label.setWordWrap(True)
        self.startup_quote_label.setToolTip("Random strategy quote selected on application startup.")
        self.startup_quote_label.setStyleSheet("font-size: 15px; font-weight: 600;")
        self.header_logo_label = QLabel()
        self.header_logo_label.setFixedSize(64, 64)
        self.header_logo_label.setAlignment(Qt.AlignCenter)
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItem("Safe Scan", "safe")
        self.scan_mode_combo.addItem("Verbose Scan", "verbose")
        self.scan_mode_combo.addItem("Aggressive Local Scan", "aggressive")
        self.localhost_protocol_combo = QComboBox()
        self.localhost_protocol_combo.addItem("TCP Only", "tcp")
        self.localhost_protocol_combo.addItem("UDP Only", "udp")
        self.localhost_protocol_combo.addItem("TCP + UDP", "both")
        self.run_scan_button = QPushButton("Run Scan")
        self.run_scan_button.setToolTip("Run the selected local audit scan.")
        self.run_scan_button.clicked.connect(self.run_scan)
        self.vulnerability_review_button = QPushButton("Aggressive Local Vulnerability Review")
        self.vulnerability_review_button.clicked.connect(self.run_aggressive_local_vulnerability_review)
        self.full_localhost_scan_button = QPushButton("Full Localhost Port Scan")
        self.full_localhost_scan_button.clicked.connect(self.run_full_localhost_port_scan)
        self.network_discovery_button = QPushButton("Local Network Device Discovery")
        self.network_discovery_button.clicked.connect(self.run_network_discovery)
        self.reset_scan_button = QPushButton("Reset / New Scan")
        self.reset_scan_button.setToolTip("Clear the current scan view and start a fresh review.")
        self.reset_scan_button.clicked.connect(self.reset_scan_state)
        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_json)
        self.export_html_button = QPushButton("Export HTML")
        self.export_html_button.clicked.connect(self.export_html)
        self.open_reports_folder_button = QPushButton("Open Reports Folder")
        self.open_reports_folder_button.setToolTip("Open the local reports folder.")
        self.open_reports_folder_button.clicked.connect(self.open_reports_folder)
        self.dashboard_primary_actions = self._build_dashboard_action_group(
            "Primary Actions",
            [self.scan_mode_combo, self.run_scan_button, self.reset_scan_button],
        )
        self.dashboard_report_actions = self._build_dashboard_action_group(
            "Reports",
            [self.export_json_button, self.export_html_button, self.open_reports_folder_button],
        )
        self.dashboard_advanced_note = QFrame()
        advanced_note_layout = QVBoxLayout(self.dashboard_advanced_note)
        advanced_note_layout.setContentsMargins(8, 6, 8, 6)
        advanced_note_layout.setSpacing(4)
        advanced_note_title = QLabel("Advanced Actions")
        advanced_note_title.setStyleSheet("font-weight: 700; color: #D6E4FF;")
        advanced_note_body = QLabel("Localhost port scans, vulnerability review, packet capture, and network discovery are available from the Diagnostics and Advanced Evidence menus.")
        advanced_note_body.setWordWrap(True)
        advanced_note_body.setStyleSheet("color: #9DB0C9;")
        advanced_note_layout.addWidget(advanced_note_title)
        advanced_note_layout.addWidget(advanced_note_body)
        self.dashboard_header_widgets = [
            self.header_logo_label,
            self.score_label,
            self.summary_label,
            self.dashboard_primary_actions,
            self.dashboard_report_actions,
            self.dashboard_advanced_note,
        ]
        self._arrange_dashboard_header()
        self.dashboard_logo_label = ClickableLabel()
        self.dashboard_logo_label.setFixedSize(160, 160)
        self.dashboard_logo_label.setAlignment(Qt.AlignCenter)
        self.dashboard_logo_label.setCursor(Qt.PointingHandCursor)
        self.dashboard_logo_label.setToolTip("Open the Mac Audit Agent usage guide")
        self.dashboard_logo_label.clicked.connect(self.show_usage_readme)
        self._apply_logo_to_label(self.header_logo_label, 64, 64, name="logo.png", rounded=True, radius=14.0)
        self._apply_logo_to_label(self.dashboard_logo_label, 160, 160, name="logo2.png", rounded=True, radius=24.0)

        self.dashboard_forecast_frame = QFrame()
        self.dashboard_forecast_frame.setObjectName("dashboardForecastSummary")
        self.dashboard_forecast_frame.setStyleSheet(
            """
            QFrame#dashboardForecastSummary {
                background: rgba(24, 31, 46, 220);
                border: 1px solid rgba(88, 166, 255, 120);
                border-radius: 12px;
            }
            """
        )
        forecast_layout = QVBoxLayout(self.dashboard_forecast_frame)
        forecast_layout.setContentsMargins(14, 14, 14, 14)
        forecast_layout.setSpacing(6)
        forecast_title = QLabel("Apple Security Forecast")
        forecast_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #F0F6FC;")
        self.dashboard_forecast_level_label = QLabel("Level: Forecast not checked yet")
        self.dashboard_forecast_last_checked_label = QLabel("Last checked: not yet")
        self.dashboard_forecast_cards_label = QLabel("Cards: 0")
        self.dashboard_forecast_kev_label = QLabel("KEV: 0")
        for label in [
            self.dashboard_forecast_level_label,
            self.dashboard_forecast_last_checked_label,
            self.dashboard_forecast_cards_label,
            self.dashboard_forecast_kev_label,
        ]:
            label.setStyleSheet("color: #D6E4FF;")
        self.open_forecast_button = make_forecast_button("Show Forecast", "Keep the Dashboard selected and focus the Apple Security Forecast section below.", "primary")
        self.open_forecast_button.clicked.connect(self.show_forecast_page)
        forecast_layout.addWidget(forecast_title)
        forecast_layout.addWidget(self.dashboard_forecast_level_label)
        forecast_layout.addWidget(self.dashboard_forecast_last_checked_label)
        forecast_layout.addWidget(self.dashboard_forecast_cards_label)
        forecast_layout.addWidget(self.dashboard_forecast_kev_label)
        forecast_layout.addWidget(self.open_forecast_button)

        self.dashboard_health_frame = QFrame()
        self.dashboard_health_frame.setObjectName("dashboardHealthSummary")
        self.dashboard_health_frame.setStyleSheet(
            """
            QFrame#dashboardHealthSummary {
                background: rgba(24, 31, 46, 220);
                border: 1px solid rgba(151, 190, 255, 100);
                border-radius: 12px;
            }
            """
        )
        health_layout = QVBoxLayout(self.dashboard_health_frame)
        health_layout.setContentsMargins(14, 14, 14, 14)
        health_layout.setSpacing(6)
        health_title = QLabel("Operational Health")
        health_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #F0F6FC;")
        self.dashboard_health_status_label = QLabel("Status: not checked yet")
        self.dashboard_health_score_label = QLabel("Score: 0/100")
        self.dashboard_health_summary_label = QLabel("Open Settings to inspect the full health dashboard.")
        self.dashboard_health_summary_label.setWordWrap(True)
        for label in [self.dashboard_health_status_label, self.dashboard_health_score_label, self.dashboard_health_summary_label]:
            label.setStyleSheet("color: #D6E4FF;")
        self.open_health_button = QPushButton("Open Health")
        self.open_health_button.setMinimumHeight(36)
        self.open_health_button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.open_health_button.setToolTip("Open the operational health dashboard in Settings.")
        self.open_health_button.clicked.connect(self.show_settings_page)
        health_layout.addWidget(health_title)
        health_layout.addWidget(self.dashboard_health_status_label)
        health_layout.addWidget(self.dashboard_health_score_label)
        health_layout.addWidget(self.dashboard_health_summary_label)
        health_layout.addWidget(self.open_health_button)

        privacy = QLabel(
            "Privacy warning: shell history review stores only matched indicators and counts by default. "
            "Snippets are redacted and context is disabled unless you change the configuration."
        )
        privacy.setWordWrap(True)

        layout.addWidget(self.dashboard_forecast_frame)
        layout.addWidget(self.dashboard_health_frame)
        layout.addWidget(self.cve_radar_panel)
        self.dashboard_cards = {}
        self.severity_cards = {}
        self.dashboard_card_widgets: list[QFrame] = []
        self.severity_card_widgets: list[QFrame] = []
        cards_frame = QFrame()
        self.cards_layout = QGridLayout(cards_frame)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(8)
        for index, label in enumerate(
            [
                "Suspicious ports",
                "Users/admin changes",
                "Shell history indicators",
                "Suspicious directories",
                "New since last scan",
            ]
        ):
            card = QFrame()
            card_layout = QVBoxLayout(card)
            title = QLabel(label)
            title.setWordWrap(True)
            value = QLabel("0")
            value.setStyleSheet("font-size: 28px; font-weight: 700;")
            card_layout.addWidget(title)
            card_layout.addWidget(value)
            self.cards_layout.addWidget(card, 0, index)
            self.dashboard_cards[label] = value
            self.dashboard_card_widgets.append(card)

        severity_frame = QFrame()
        self.severity_layout = QGridLayout(severity_frame)
        self.severity_layout.setContentsMargins(0, 0, 0, 0)
        self.severity_layout.setSpacing(8)
        for index, severity in enumerate(["info", "low", "medium", "high", "critical"]):
            card = QFrame()
            bg, fg = severity_qcolors(severity)
            card.setStyleSheet(f"background-color: {bg.name()}; color: {fg.name()}; border-radius: 10px;")
            card_layout = QVBoxLayout(card)
            title = QLabel(severity.title())
            title.setStyleSheet(f"color: {fg.name()}; font-weight: 700;")
            title.setWordWrap(True)
            value = QLabel("0")
            value.setStyleSheet(f"font-size: 24px; font-weight: 700; color: {fg.name()};")
            card_layout.addWidget(title)
            card_layout.addWidget(value)
            self.severity_layout.addWidget(card, 0, index)
            self.severity_cards[severity] = value
            self.severity_card_widgets.append(card)

        layout.addWidget(header)
        layout.addWidget(self.startup_quote_label)
        layout.addWidget(self.dashboard_logo_label, alignment=Qt.AlignHCenter)
        layout.addWidget(privacy)
        layout.addWidget(cards_frame)
        layout.addWidget(severity_frame)
        layout.addStretch(1)
        return page

    def _build_categories_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        self.categories_table = QTableWidget(0, 4)
        self.categories_table.setHorizontalHeaderLabels(["Category", "Command", "Risk", "Preview"])
        self.categories_table.itemSelectionChanged.connect(self._update_command_preview_from_selection)
        self.categories_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.categories_table)
        return page

    def _build_intrusion_detection_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.intrusion_detection_panel)
        return page

    def _build_family_safety_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.family_safety_panel)
        return page

    def _build_investigation_priorities_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.investigation_priority_nav_panel)
        return page

    def _build_flight_recorder_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.flight_recorder_panel)
        return page

    def _build_results_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        self.results_empty_state = QFrame()
        self.results_empty_state.setProperty("themeCard", True)
        empty_layout = QVBoxLayout(self.results_empty_state)
        empty_layout.setContentsMargins(14, 14, 14, 14)
        empty_layout.setSpacing(8)
        empty_title = QLabel("No results available yet.")
        empty_title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        empty_body = QLabel("Run Safe Scan from the Dashboard to populate findings, ports, users, evidence, workflow details, and report exports.")
        empty_body.setWordWrap(True)
        empty_body.setStyleSheet("color: #D6E4FF;")
        empty_action = QPushButton("Go to Dashboard")
        empty_action.setProperty("role", "primary")
        empty_action.clicked.connect(lambda: self._show_sidebar_page("Dashboard"))
        empty_layout.addWidget(empty_title)
        empty_layout.addWidget(empty_body)
        empty_layout.addWidget(empty_action)
        empty_layout.addStretch(1)
        self.results_tabs = QTabWidget()
        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        findings_layout.setContentsMargins(8, 8, 8, 8)
        findings_controls = QHBoxLayout()
        findings_controls.addWidget(QLabel("Priority Order"))
        self.findings_sort_combo = QComboBox()
        self.findings_sort_combo.addItem("Critical -> Low", "critical_to_low")
        self.findings_sort_combo.addItem("Low -> Critical", "low_to_critical")
        self.findings_sort_combo.currentIndexChanged.connect(self._change_findings_sort_order)
        findings_controls.addWidget(self.findings_sort_combo)
        findings_controls.addStretch(1)
        self.findings_table = self._make_table(["Severity", "Category", "Title", "Evidence Summary"])
        self.findings_table.itemSelectionChanged.connect(self._update_selected_finding_panel)
        findings_layout.addLayout(findings_controls)
        findings_layout.addWidget(self.findings_table)
        self.ports_table = self._make_table(["Process", "PID", "Local Address", "Port", "Concern"])
        self.processes_table = self._make_table(["User", "PID", "PPID", "Path", "Trust", "Score", "Reasons"])
        self.catalog_status_table = self._make_table(["Field", "Value"])
        cve_findings_page = QWidget()
        cve_findings_layout = QVBoxLayout(cve_findings_page)
        cve_filters = QHBoxLayout()
        self.cve_filter_kev_only = QCheckBox("KEV only")
        self.cve_filter_epss_high = QCheckBox("EPSS high")
        self.cve_filter_critical_high = QCheckBox("Critical/High")
        self.cve_filter_installed_only = QCheckBox("Installed software only")
        self.cve_filter_macos_only = QCheckBox("macOS config only")
        for widget in [
            self.cve_filter_kev_only,
            self.cve_filter_epss_high,
            self.cve_filter_critical_high,
            self.cve_filter_installed_only,
            self.cve_filter_macos_only,
        ]:
            widget.stateChanged.connect(self._apply_vulnerability_filters)
            cve_filters.addWidget(widget)
        cve_filters.addStretch(1)
        self.cve_findings_table = self._make_table(["Severity", "Product", "Version", "CVE", "KEV", "EPSS", "CVSS", "Confidence", "Title"])
        cve_findings_layout.addLayout(cve_filters)
        cve_findings_layout.addWidget(self.cve_findings_table)
        self.best_practice_findings_table = self._make_table(["Severity", "Category", "Title", "Evidence"])
        self.review_needed_findings_table = self._make_table(["Severity", "Product", "Version", "CVE", "Confidence", "Title"])
        self.users_table = self._make_table(["User", "UID", "Admin", "Hidden", "Shell", "Auth Keys", "Home"])
        self.history_table = self._make_table(["Shell", "Pattern", "Matches", "Source", "Snippet"])
        self.files_table = self._make_table(["Path", "Issue", "Modified", "Signed", "Trust", "Score"])
        self.comparison_table = self._make_table(["Change Type", "Item Key", "Details"])
        self.logs_table = self._make_table(["Collector", "Source", "Timestamp", "Exit", "stderr", "stdout"])
        self.localhost_scan_table = self._make_table(["Field", "Value"])
        self.localhost_full_scan_table = self._make_table(["Field", "Value"])
        self.packet_capture_table = self._make_table(["Field", "Value"])
        self.network_discovery_page = QWidget()
        network_layout = QVBoxLayout(self.network_discovery_page)
        network_layout.setContentsMargins(8, 8, 8, 8)
        network_layout.addWidget(QLabel("This identifies devices visible on your local network. Unknown devices are not proof of compromise, but should be reviewed."))
        self.network_discovery_summary_table = self._make_table(["Field", "Value"])
        self.network_discovery_hosts_table = self._make_table(["IP Address", "Likely Hostname", "MAC Address", "Vendor", "Device Type", "Confidence", "Discovery Methods", "Review Flags"])
        self.network_discovery_device_details_table = self._make_table(["Field", "Value"])
        self.network_discovery_debug_table = self._make_table(["Stage", "Value"])
        self.network_discovery_changes_table = self._make_table(["Change", "Details"])
        self.network_discovery_suspicious_table = self._make_table(["Severity", "Title", "Evidence"])
        network_layout.addWidget(self.network_discovery_summary_table)
        network_layout.addWidget(QLabel("Discovered Hosts"))
        network_layout.addWidget(self.network_discovery_hosts_table)
        network_layout.addWidget(QLabel("Selected Device Details"))
        network_layout.addWidget(self.network_discovery_device_details_table)
        network_layout.addWidget(QLabel("Baseline Changes"))
        network_layout.addWidget(self.network_discovery_changes_table)
        network_layout.addWidget(QLabel("Discovery Debug"))
        network_layout.addWidget(self.network_discovery_debug_table)
        network_layout.addWidget(QLabel("Suspicious / Review Needed Devices"))
        network_layout.addWidget(self.network_discovery_suspicious_table)
        self.network_discovery_hosts_table.itemSelectionChanged.connect(self._refresh_network_discovery_device_details)
        self.workflow_page = QWidget()
        workflow_layout = QVBoxLayout(self.workflow_page)
        workflow_layout.setContentsMargins(8, 8, 8, 8)
        workflow_layout.addWidget(QLabel("Workflow view: what changed, what to review, and what the evidence supports."))
        self.workflow_replay_table = self._make_table(["Timestamp", "Type", "Title", "Summary"])
        self.workflow_review_queue_table = self._make_table(["Priority", "Severity", "Confidence", "State", "Suppressed", "Title", "Next Action"])
        self.workflow_explanation_table = self._make_table(["Field", "Value"])
        self.workflow_review_queue_table.itemSelectionChanged.connect(self._refresh_workflow_explanation)
        workflow_layout.addWidget(QLabel("Replay Timeline"))
        workflow_layout.addWidget(self.workflow_replay_table)
        workflow_layout.addWidget(QLabel("Review Queue"))
        workflow_layout.addWidget(self.workflow_review_queue_table)
        workflow_layout.addWidget(QLabel("Explainability"))
        workflow_layout.addWidget(self.workflow_explanation_table)
        self.execution_evidence_page = QWidget()
        execution_layout = QVBoxLayout(self.execution_evidence_page)
        execution_layout.setContentsMargins(8, 8, 8, 8)
        execution_layout.addWidget(QLabel("Execution Evidence view: evidence only, no compromise claims."))
        self.execution_evidence_table = self._make_table(["Confidence", "Evidence", "Timeline", "Explanation", "Recommended Actions"])
        execution_layout.addWidget(self.execution_evidence_table)
        self.investigation_priority_panel = InvestigationPriorityPanel()
        for name, widget in [
            ("Findings", findings_page),
            ("Ports", self.ports_table),
            ("Localhost Port Scan", self.localhost_scan_table),
            ("Full Localhost Port Scan", self.localhost_full_scan_table),
            ("Packet Capture Snapshot", self.packet_capture_table),
            ("Local Network Device Discovery", self.network_discovery_page),
            ("Workflow Layer", self.workflow_page),
            ("Investigation Priorities", self.investigation_priority_panel),
            ("Execution Evidence", self.execution_evidence_page),
            ("Catalog Update Status", self.catalog_status_table),
            ("CVE Findings", cve_findings_page),
            ("Best Practice Findings", self.best_practice_findings_table),
            ("Review Needed Findings", self.review_needed_findings_table),
            ("Processes", self.processes_table),
            ("Users", self.users_table),
            ("History Indicators", self.history_table),
            ("File/Directory Issues", self.files_table),
            ("Baseline Comparison", self.comparison_table),
            ("Raw Logs", self.logs_table),
        ]:
            self.results_tabs.addTab(widget, name)
        layout.addWidget(self.results_empty_state)
        layout.addWidget(self.results_tabs)
        self._set_results_available(self.current_scan_result is not None)
        return page

    def _build_logs_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.logs_panel)
        return page

    def _build_forecast_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.cve_radar_panel)
        return page

    def _build_system_recovery_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.system_recovery_panel)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        health_label = QLabel("Operational Health")
        health_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        health_label.setWordWrap(True)
        layout.addWidget(health_label)
        layout.addWidget(self.operational_health_panel)
        monitor_label = QLabel("Monitor Settings")
        monitor_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        monitor_label.setWordWrap(True)
        layout.addWidget(monitor_label)
        layout.addWidget(self.background_monitor_panel)
        return page

    def _build_skins_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.theme_panel)
        return page

    def _build_preview_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        heading = QLabel("Audit Command Preview")
        heading.setStyleSheet("font-size: 18px; font-weight: 700;")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        explainer = QLabel(
            "This tab previews read-only audit and evidence-collection commands registered in Mac Audit Agent. "
            "It is not a complete list of possible remediation commands, and it does not mean every listed command ran during the last scan."
        )
        explainer.setWordWrap(True)
        layout.addWidget(explainer)
        self.command_preview = QTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.command_preview)
        self.command_preview.setPlainText(self._default_command_preview_text())
        return page

    def _build_investigation_notes_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        warning = QLabel(
            "Investigation Notes may contain sensitive case information. Notes stay local to this Mac and are only included in exports when you explicitly choose to include them."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.investigation_progress_label = QLabel("No scan loaded.")
        layout.addWidget(self.investigation_progress_label)
        note_header = QHBoxLayout()
        self.investigation_note_title = QLineEdit()
        self.investigation_note_title.setPlaceholderText("Notes title")
        self.investigation_investigator_name = QLineEdit()
        self.investigation_investigator_name.setPlaceholderText("Investigator name (optional)")
        note_header.addWidget(self.investigation_note_title)
        note_header.addWidget(self.investigation_investigator_name)
        layout.addLayout(note_header)
        self.investigation_notes_editor = QTextEdit()
        self.investigation_notes_editor.setPlaceholderText("Document what you reviewed, what remains open, and any case notes.")
        layout.addWidget(self.investigation_notes_editor)
        action_row = QHBoxLayout()
        self.save_investigation_notes_button = QPushButton("Save")
        self.save_investigation_notes_button.clicked.connect(self.save_investigation_notes)
        self.export_investigation_notes_json_button = QPushButton("Export Notes JSON")
        self.export_investigation_notes_json_button.clicked.connect(self.export_investigation_notes_json_file)
        self.export_investigation_notes_html_button = QPushButton("Export Notes HTML")
        self.export_investigation_notes_html_button.clicked.connect(self.export_investigation_notes_html_file)
        self.last_saved_investigation_label = QLabel("Last saved: never")
        action_row.addWidget(self.save_investigation_notes_button)
        action_row.addWidget(self.export_investigation_notes_json_button)
        action_row.addWidget(self.export_investigation_notes_html_button)
        action_row.addStretch(1)
        action_row.addWidget(self.last_saved_investigation_label)
        layout.addLayout(action_row)
        layout.addWidget(QLabel("Reviewed Checklist"))
        self.investigation_checklist_table = self._make_table(["Type", "Item", "Status"])
        layout.addWidget(self.investigation_checklist_table)
        layout.addWidget(QLabel("Finding-Linked Notes"))
        self.finding_notes_table = self._make_table(["Updated", "Finding", "Title", "Status", "Priority"])
        layout.addWidget(self.finding_notes_table)
        layout.addWidget(QLabel("Timeline Notes"))
        self.timeline_notes_table = self._make_table(["Timestamp", "Action", "Entity", "Details", "Previous", "New"])
        layout.addWidget(self.timeline_notes_table)
        self.investigation_autosave_timer = QTimer(self)
        self.investigation_autosave_timer.setInterval(30_000)
        self.investigation_autosave_timer.timeout.connect(self._autosave_investigation_notes)
        self.investigation_autosave_timer.start()
        self.current_investigation_note_id = ""
        return page

    def _build_background_monitor_page(self) -> QWidget:
        self.background_monitor_panel = BackgroundMonitorPanel(self.db, self.launch_agent_manager, self)
        return self.background_monitor_panel

    def _build_selected_command_panel(self) -> QFrame:
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        details_heading = QLabel("Selected Item Details")
        details_heading.setStyleSheet("font-weight: 700;")
        details_heading.setWordWrap(True)
        layout.addWidget(details_heading)
        details_hint = QLabel("Shows either the selected audit command metadata or the selected finding evidence. Finding details are separate from the Command Preview tab.")
        details_hint.setWordWrap(True)
        layout.addWidget(details_hint)
        self.selected_command_panel = QTextEdit()
        self.selected_command_panel.setReadOnly(True)
        self.selected_command_panel.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.selected_command_panel)
        remediation_heading = QLabel("Finding Remediation Guidance")
        remediation_heading.setStyleSheet("font-weight: 700;")
        remediation_heading.setWordWrap(True)
        layout.addWidget(remediation_heading)
        remediation_hint = QLabel(
            "Appears only for selected findings. Copyable commands are optional helper commands, not the only remediation path. Review the steps, impact, and verification guidance before acting."
        )
        remediation_hint.setWordWrap(True)
        layout.addWidget(remediation_hint)
        self.remediation_panel = QTextEdit()
        self.remediation_panel.setReadOnly(True)
        self.remediation_panel.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.remediation_panel)
        self.remediation_actions_frame = QFrame()
        command_row = QHBoxLayout(self.remediation_actions_frame)
        command_row.setContentsMargins(0, 0, 0, 0)
        self.remediation_command_selector = QComboBox()
        self.remediation_command_selector.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.copy_command_button = QPushButton("Copy Command")
        self.copy_command_button.setToolTip("Copy the selected remediation command.")
        self.copy_command_button.clicked.connect(self.copy_remediation_command)
        self.run_command_button = QPushButton("Run Command")
        self.run_command_button.setToolTip("Run the selected remediation command after confirmation.")
        self.run_command_button.clicked.connect(self.run_remediation_command)
        command_row.addWidget(self.remediation_command_selector)
        command_row.addWidget(self.copy_command_button)
        command_row.addWidget(self.run_command_button)
        layout.addWidget(self.remediation_actions_frame)
        self.review_actions_frame = QFrame()
        review_actions = QGridLayout(self.review_actions_frame)
        review_actions.setContentsMargins(0, 0, 0, 0)
        self.add_finding_note_button = QPushButton("Add Note")
        self.add_finding_note_button.clicked.connect(self.add_note_for_selected_finding)
        self.mark_reviewed_button = QPushButton("Mark Reviewed")
        self.mark_reviewed_button.clicked.connect(lambda: self._set_selected_finding_review_state("reviewed"))
        self.mark_false_positive_button = QPushButton("Mark False Positive")
        self.mark_false_positive_button.clicked.connect(lambda: self._set_selected_finding_review_state("false positive"))
        self.mark_confirmed_button = QPushButton("Mark Confirmed Concern")
        self.mark_confirmed_button.clicked.connect(lambda: self._set_selected_finding_review_state("confirmed concern"))
        self.mark_follow_up_button = QPushButton("Mark Needs Follow-Up")
        self.mark_follow_up_button.clicked.connect(lambda: self._set_selected_finding_review_state("needs follow-up"))
        self.show_context_button = QPushButton("Show Context")
        self.show_context_button.clicked.connect(self.show_selected_finding_context)
        self.show_provenance_button = QPushButton("Why did this alert fire?")
        self.show_provenance_button.clicked.connect(self.show_selected_finding_provenance)
        for index, widget in enumerate(
            [
                self.add_finding_note_button,
                self.mark_reviewed_button,
                self.mark_false_positive_button,
                self.mark_confirmed_button,
                self.mark_follow_up_button,
                self.show_context_button,
                self.show_provenance_button,
            ]
        ):
            review_actions.addWidget(widget, index // 2, index % 2)
        self.selected_finding_hint_label = QLabel("Select a finding in Results to review details, remediation, notes, and context actions.")
        self.selected_finding_hint_label.setWordWrap(True)
        self.selected_finding_hint_label.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(self.selected_finding_hint_label)
        layout.addWidget(self.review_actions_frame)
        layout.addStretch(1)
        self._clear_selected_finding_panel()
        return panel

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setStretchLastSection(True)
        table.setWordWrap(True)
        return table

    def _set_results_available(self, available: bool) -> None:
        if hasattr(self, "results_empty_state"):
            self.results_empty_state.setVisible(not available)
        if hasattr(self, "results_tabs"):
            self.results_tabs.setVisible(available)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_responsive_layout()

    def _update_responsive_layout(self) -> None:
        if not hasattr(self, "main_splitter"):
            return
        width = max(self.width(), 1)
        height = max(self.height(), 1)
        low_aspect = (width / height) < 1.55 or width < 1200
        self.main_splitter.setOrientation(Qt.Vertical if low_aspect else Qt.Horizontal)
        if low_aspect:
            self.main_splitter.setSizes([int(height * 0.62), int(height * 0.38)])
        else:
            self.main_splitter.setSizes([int(width * 0.72), int(width * 0.28)])
        self._arrange_dashboard_header()
        self._arrange_dashboard_cards()

    def _arrange_dashboard_header(self) -> None:
        if not hasattr(self, "dashboard_header_layout"):
            return
        while self.dashboard_header_layout.count():
            item = self.dashboard_header_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        columns = 2 if self.width() < 1200 else 4
        for index, widget in enumerate(self.dashboard_header_widgets):
            row = index // columns
            column = index % columns
            self.dashboard_header_layout.addWidget(widget, row, column)

    def _load_logo_pixmap(self, width: int, height: int, name: str = "logo.png") -> QPixmap:
        path = get_asset_path(name)
        if not path.exists():
            return QPixmap()
        pixmap = QPixmap(str(path))
        if pixmap.isNull():
            return QPixmap()
        return pixmap.scaled(width, height, Qt.KeepAspectRatio, Qt.SmoothTransformation)

    def _rounded_pixmap(self, pixmap: QPixmap, radius: float) -> QPixmap:
        if pixmap.isNull():
            return QPixmap()
        rounded = QPixmap(pixmap.size())
        rounded.fill(Qt.transparent)
        painter = QPainter(rounded)
        painter.setRenderHint(QPainter.Antialiasing, True)
        path = QPainterPath()
        path.addRoundedRect(rounded.rect(), radius, radius)
        painter.setClipPath(path)
        painter.drawPixmap(0, 0, pixmap)
        painter.end()
        return rounded

    def _apply_logo_to_label(
        self,
        label: QLabel,
        width: int,
        height: int,
        *,
        name: str = "logo.png",
        rounded: bool = False,
        radius: float = 18.0,
    ) -> None:
        pixmap = self._load_logo_pixmap(width, height, name=name)
        if pixmap.isNull():
            label.clear()
            label.setVisible(False)
            return
        if rounded:
            pixmap = self._rounded_pixmap(pixmap, radius)
        label.setPixmap(pixmap)
        label.setVisible(True)

    def show_about_dialog(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle(ABOUT_TITLE)
        layout = QVBoxLayout(dialog)
        logo_label = QLabel()
        logo_label.setAlignment(Qt.AlignCenter)
        self._apply_logo_to_label(logo_label, 128, 128)
        logo_pixmap = logo_label.pixmap()
        if logo_pixmap is not None and not logo_pixmap.isNull():
            layout.addWidget(logo_label)
        title = QLabel(APP_TITLE)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        layout.addWidget(title)
        summary = QLabel(
            "Local-first macOS security auditing with transparent collection, defensive reporting, and background privacy monitoring."
        )
        summary.setWordWrap(True)
        summary.setAlignment(Qt.AlignCenter)
        layout.addWidget(summary)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    def _usage_readme_path(self) -> Path:
        bundle_root = getattr(sys, "_MEIPASS", None)
        if bundle_root:
            bundled = Path(bundle_root) / "README.md"
            if bundled.exists():
                return bundled
        return Path(__file__).resolve().parents[2] / "README.md"

    def show_usage_readme(self) -> None:
        readme_path = self._usage_readme_path()
        if not readme_path.exists():
            QMessageBox.warning(self, "Usage Guide Missing", f"README not found at:\n{readme_path}")
            return
        try:
            content = readme_path.read_text(encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Usage Guide Error", f"Failed to open README:\n{exc}")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(USAGE_GUIDE_TITLE)
        dialog.resize(900, 700)
        layout = QVBoxLayout(dialog)
        title = QLabel(f"{APP_TITLE} Usage Guide")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        layout.addWidget(title)
        viewer = QTextEdit()
        viewer.setReadOnly(True)
        viewer.setMarkdown(content)
        layout.addWidget(viewer)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    def _current_scan_id(self) -> str:
        if self.current_scan_result is not None:
            return self.current_scan_result.scan_id
        if self.current_scan_summary is not None:
            return self.current_scan_summary.scan_id
        return ""

    def _autosave_investigation_notes(self) -> None:
        if not hasattr(self, "investigation_notes_editor"):
            return
        if not self._current_scan_id():
            return
        self.save_investigation_notes(auto=True)

    def save_investigation_notes(self, *, auto: bool = False) -> None:
        scan_id = self._current_scan_id()
        if not scan_id:
            if not auto:
                QMessageBox.information(self, "No Scan", "Run or load a scan before saving investigation notes.")
            return
        title = self.investigation_note_title.text().strip() or "Investigation Overview"
        note = InvestigationNote(
            note_id=self.current_investigation_note_id or "",
            created_at=utc_now_iso(),
            updated_at=utc_now_iso(),
            title=title,
            body=self.investigation_notes_editor.toPlainText(),
            linked_scan_id=scan_id,
            investigator_name=self.investigation_investigator_name.text().strip(),
        )
        existing = self.db.get_general_investigation_note(scan_id)
        if existing.title == title or not self.current_investigation_note_id:
            note.note_id = existing.note_id
            note.created_at = existing.created_at
        note_id = self.db.save_investigation_note(note)
        self.current_investigation_note_id = note_id
        saved_at = utc_now_iso()
        self.last_saved_investigation_label.setText(f"Last saved: {saved_at}")
        if not auto:
            self.statusBar().showMessage("investigation notes saved", 5000)
        self.refresh_investigation_notes_page()

    def refresh_investigation_notes_page(self) -> None:
        if not hasattr(self, "investigation_notes_editor"):
            return
        scan_id = self._current_scan_id()
        if not scan_id:
            self.investigation_progress_label.setText("No scan loaded.")
            return
        general_note = self.db.get_general_investigation_note(scan_id)
        if not self.investigation_notes_editor.hasFocus():
            self.investigation_note_title.setText(general_note.title)
            self.investigation_notes_editor.setPlainText(general_note.body)
            self.investigation_investigator_name.setText(general_note.investigator_name)
        self.current_investigation_note_id = general_note.note_id
        notes = [item.to_dict() for item in self.db.list_investigation_notes(linked_scan_id=scan_id, limit=1000)]
        progress = self.db.investigation_progress(scan_id, len(self.current_visible_findings or normalize_findings((self.current_payload or {}).get("findings", []))))
        self.investigation_progress_label.setText(
            " | ".join(
                [
                    f"Total findings: {progress['total_findings']}",
                    f"Reviewed: {progress['reviewed_count']}",
                    f"Unreviewed: {progress['unreviewed_count']}",
                    f"Follow-up: {progress['follow_up_count']}",
                    f"Confirmed concerns: {progress['confirmed_concerns']}",
                    f"False positives: {progress['false_positives']}",
                    f"Progress: {progress['progress_percentage']}%",
                ]
            )
        )
        self._populate_investigation_checklist(scan_id)
        self._populate_table(
            self.finding_notes_table,
            [
                [
                    str(item.get("updated_at", "")),
                    str(item.get("linked_finding_id", "")),
                    str(item.get("title", "")),
                    str(item.get("status", "")),
                    str(item.get("priority", "")),
                ]
                for item in notes
                if item.get("linked_finding_id")
            ],
        )
        self._populate_table(
            self.timeline_notes_table,
            [
                [
                    entry.timestamp,
                    entry.action_type,
                    entry.entity_type,
                    entry.details,
                    entry.previous_status,
                    entry.new_status,
                ]
                for entry in self.db.list_investigation_audit_trail(limit=250)
            ],
        )

    def _investigation_review_items(self, scan_id: str) -> list[dict[str, str]]:
        payload = self.current_payload or {}
        findings = normalize_findings(payload.get("findings", []))
        ports = payload.get("ports", []) or payload.get("collected_artifacts", {}).get("ports", {}).get("listening", [])
        processes = payload.get("processes", []) or payload.get("collected_artifacts", {}).get("processes", {}).get("all", [])
        launch_items = payload.get("launch_snapshots", []) or payload.get("collected_artifacts", {}).get("launch_snapshots", [])
        users = payload.get("users", [])
        packet_captures = payload.get("collected_artifacts", {}).get("packet_captures", []) if payload else []
        devices = payload.get("collected_artifacts", {}).get("network_discovery", {}).get("hosts", []) if payload else []
        monitor_events = [item.to_dict() for item in self.db.recent_background_monitor_events(limit=100)]
        items: list[dict[str, str]] = []
        items.extend({"type": "finding", "key": str(item.get("id", "")), "label": str(item.get("title", "")), "finding_id": str(item.get("id", ""))} for item in findings)
        items.extend({"type": "port", "key": f"{item.get('process_name', '')}:{item.get('port', '')}:{item.get('local_address', '')}", "label": f"{item.get('process_name', '')} {item.get('local_address', '')}", "finding_id": ""} for item in [finding_to_dict(item) for item in ports])
        items.extend({"type": "process", "key": f"{item.get('process_name', '')}:{item.get('pid', '')}", "label": f"{item.get('process_name', '')} pid={item.get('pid', '')}", "finding_id": ""} for item in [finding_to_dict(item) for item in processes])
        items.extend({"type": "persistence_item", "key": str(item.get('path', item.get('label', ''))), "label": str(item.get('path', item.get('label', ''))), "finding_id": ""} for item in [finding_to_dict(item) for item in launch_items])
        items.extend({"type": "user_change", "key": str(item.get('username', item.get('user', ''))), "label": str(item.get('username', item.get('user', ''))), "finding_id": ""} for item in [finding_to_dict(item) for item in users])
        items.extend({"type": "packet_capture", "key": str(item.get('capture_id', '')), "label": str(item.get('capture_id', '')), "finding_id": ""} for item in [finding_to_dict(item) for item in packet_captures])
        items.extend(
            {
                "type": "device_inventory",
                "key": str(item.get("ip_address", "")),
                "label": str(item.get("likely_hostname", item.get("hostname", "Unknown Host")) or "Unknown Host"),
                "finding_id": "",
            }
            for item in [finding_to_dict(item) for item in devices]
        )
        items.extend({"type": "monitor_event", "key": str(item.get('event_id', '')), "label": str(item.get('event_type', '')), "finding_id": ""} for item in monitor_events)
        return [item for item in items if item["key"]]

    def _populate_investigation_checklist(self, scan_id: str) -> None:
        review_statuses = self.db.get_review_statuses(scan_id)
        table = self.investigation_checklist_table
        table.setRowCount(0)
        for item in self._investigation_review_items(scan_id):
            status = review_statuses.get((item["type"], item["key"]))
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(item["type"]))
            table.setItem(row, 1, QTableWidgetItem(item["label"]))
            combo = QComboBox()
            for review_state in REVIEW_STATES:
                combo.addItem(review_state)
            combo.setCurrentText(status.review_state if status else "not reviewed")
            combo.currentTextChanged.connect(
                lambda value, item=item: self.db.set_review_status(
                    item_type=item["type"],
                    item_key=item["key"],
                    label=item["label"],
                    review_state=value,
                    linked_scan_id=scan_id,
                    linked_finding_id=item["finding_id"],
                )
            )
            combo.currentTextChanged.connect(lambda _value: self.refresh_investigation_notes_page())
            table.setCellWidget(row, 2, combo)
        table.resizeRowsToContents()

    def add_note_for_selected_finding(self) -> None:
        if not self.current_selected_finding:
            QMessageBox.information(self, "No Finding", "Select a finding first.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Finding Note")
        layout = QVBoxLayout(dialog)
        title_input = QLineEdit()
        title_input.setPlaceholderText("Note title")
        body_input = QTextEdit()
        body_input.setPlaceholderText("Finding-specific note")
        layout.addWidget(title_input)
        layout.addWidget(body_input)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.Accepted:
            return
        finding_id = str(self.current_selected_finding.get("id", ""))
        scan_id = self._current_scan_id()
        note = InvestigationNote(
            note_id=f"note-{utc_now_iso()}",
            created_at=utc_now_iso(),
            updated_at=utc_now_iso(),
            title=title_input.text().strip() or f"Note for {finding_id}",
            body=body_input.toPlainText(),
            linked_finding_id=finding_id,
            linked_scan_id=scan_id,
        )
        self.db.save_investigation_note(note)
        self.sidebar.setCurrentRow(4)
        self.refresh_investigation_notes_page()

    def _set_selected_finding_review_state(self, state: str) -> None:
        if not self.current_selected_finding:
            QMessageBox.information(self, "No Finding", "Select a finding first.")
            return
        finding_id = str(self.current_selected_finding.get("id", ""))
        self.db.set_review_status(
            item_type="finding",
            item_key=finding_id,
            label=str(self.current_selected_finding.get("title", finding_id)),
            review_state=state,
            linked_scan_id=self._current_scan_id(),
            linked_finding_id=finding_id,
        )
        self.refresh_investigation_notes_page()

    def show_selected_finding_context(self) -> None:
        if not self.current_selected_finding:
            QMessageBox.information(self, "No Finding", "Select a finding first.")
            return
        scan = self.current_scan_result
        anchor_timestamp = scan.timestamp if scan is not None else str(self.current_selected_finding.get("created_at", "") or utc_now_iso())
        window = self.workflow_layer.build_context_window(
            anchor_timestamp,
            focus_label=str(self.current_selected_finding.get("title", "Selected finding")),
            focus_kind="finding",
            focus_category=str(self.current_selected_finding.get("category", "finding")),
            focus_id=str(self.current_selected_finding.get("id", "")),
            focus_scan_id=scan.scan_id if scan is not None else "",
        )
        ContextDialog(window, self).exec()

    def _selected_finding_provenance_text(self, finding: dict) -> str:
        hints = finding.get("false_positive_hints", []) or []
        steps = finding.get("recommended_verification_steps", []) or finding.get("verification_steps", []) or []
        lines = [
            f"Alert: {finding.get('title', '')}",
            f"Rule: {finding.get('rule_id') or finding.get('trigger_rule_id', '')} ({finding.get('rule_name') or finding.get('trigger_rule_name', '')})",
            f"Detector: {finding.get('trigger_source', '')} / {finding.get('trigger_subsource', '')}",
            f"Confidence: {finding.get('confidence', finding.get('severity', 'info'))}",
            f"Evidence: {finding.get('evidence_summary', finding.get('evidence', ''))}",
            f"Previous state: {finding.get('previous_state', '')}",
            f"Current state: {finding.get('current_state', '')}",
            f"First seen: {finding.get('first_seen', finding.get('created_at', ''))}",
            f"Last seen: {finding.get('last_seen', finding.get('created_at', ''))}",
            f"Correlation: {finding.get('correlation_id', '')}",
            f"Baseline: {finding.get('baseline_status', '')}",
            f"Possible false-positive reason: {', '.join(str(item) for item in hints) if hints else finding.get('false_positive_notes', '')}",
            f"Verification: {', '.join(str(item) for item in steps) if steps else finding.get('recommended_next_steps', '')}",
        ]
        if finding.get("raw_signal_summary"):
            lines.append(f"Raw signal: {finding.get('raw_signal_summary')}")
        if finding.get("normalized_signal"):
            lines.append(f"Normalized signal: {finding.get('normalized_signal')}")
        if finding.get("source_trace"):
            lines.append(f"Source trace: {finding.get('source_trace')}")
        if finding.get("evidence_hash"):
            lines.append(f"Evidence hash: {finding.get('evidence_hash')}")
        if finding.get("source_trace"):
            lines.append(f"Source trace: {finding.get('source_trace')}")
        return "\n".join(line for line in lines if line)

    def show_selected_finding_provenance(self) -> None:
        if not self.current_selected_finding:
            QMessageBox.information(self, "No Finding", "Select a finding first.")
            return
        scan = self.current_scan_result
        anchor_timestamp = scan.timestamp if scan is not None else str(self.current_selected_finding.get("created_at", "") or utc_now_iso())
        window = self.workflow_layer.build_context_window(
            anchor_timestamp,
            focus_label=str(self.current_selected_finding.get("title", "Selected finding")),
            focus_kind="finding",
            focus_category=str(self.current_selected_finding.get("category", "finding")),
            focus_id=str(self.current_selected_finding.get("id", "")),
            focus_scan_id=scan.scan_id if scan is not None else "",
        ).to_dict()
        body = self._selected_finding_provenance_text(self.current_selected_finding)
        AlertProvenanceDialog("Alert Provenance", body, window, self).exec()

    def export_investigation_notes_json_file(self) -> None:
        scan_id = self._current_scan_id()
        if not scan_id:
            QMessageBox.warning(self, "No Scan Data", "Load a scan before exporting notes.")
            return
        default_path = get_reports_dir() / f"investigation_notes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Investigation Notes JSON",
            str(default_path),
            "JSON Files (*.json)",
        )
        if not path:
            return
        try:
            saved_path = export_investigation_notes_json(
                [item.to_dict() for item in self.db.list_investigation_notes(linked_scan_id=scan_id, limit=1000)],
                [item.to_dict() for item in self.db.list_investigation_audit_trail(limit=1000)],
                Path(path),
            )
        except OSError as exc:
            LOGGER.exception("Failed to export investigation notes JSON to %s", path)
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export investigation notes JSON:\n{path}\n\n{exc}",
            )
            return
        QMessageBox.information(self, "Investigation Notes Exported", f"Saved investigation notes JSON to:\n{saved_path}")

    def export_investigation_notes_html_file(self) -> None:
        scan_id = self._current_scan_id()
        if not scan_id:
            QMessageBox.warning(self, "No Scan Data", "Load a scan before exporting notes.")
            return
        default_path = get_reports_dir() / f"investigation_notes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Investigation Notes HTML",
            str(default_path),
            "HTML Files (*.html)",
        )
        if not path:
            return
        try:
            saved_path = export_investigation_notes_html(
                [item.to_dict() for item in self.db.list_investigation_notes(linked_scan_id=scan_id, limit=1000)],
                [item.to_dict() for item in self.db.list_investigation_audit_trail(limit=1000)],
                Path(path),
            )
        except OSError as exc:
            LOGGER.exception("Failed to export investigation notes HTML to %s", path)
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export investigation notes HTML:\n{path}\n\n{exc}",
            )
            return
        QMessageBox.information(self, "Investigation Notes Exported", f"Saved investigation notes HTML to:\n{saved_path}")

    def _arrange_dashboard_cards(self) -> None:
        if not hasattr(self, "cards_layout") or not hasattr(self, "severity_layout"):
            return
        card_columns = 2 if self.width() < 1100 else 3 if self.width() < 1450 else 5
        for index, widget in enumerate(self.dashboard_card_widgets):
            row = index // card_columns
            column = index % card_columns
            self.cards_layout.addWidget(widget, row, column)
        severity_columns = 2 if self.width() < 1100 else 3 if self.width() < 1450 else 5
        for index, widget in enumerate(self.severity_card_widgets):
            row = index // severity_columns
            column = index % severity_columns
            self.severity_layout.addWidget(widget, row, column)

    def _load_registry(self) -> None:
        self.categories_table.setRowCount(0)
        for command in self.registry.values():
            row = self.categories_table.rowCount()
            self.categories_table.insertRow(row)
            self.categories_table.setItem(row, 0, QTableWidgetItem(command.category))
            self.categories_table.setItem(row, 1, QTableWidgetItem(command.name))
            risk_item = QTableWidgetItem(command.risk_level)
            risk_item.setForeground(QColor(RISK_COLORS[command.risk_level]))
            self.categories_table.setItem(row, 2, risk_item)
            self.categories_table.setItem(row, 3, QTableWidgetItem(self.runner.preview_command(command)))
        self._refresh_command_preview_page()

    def _update_command_preview_from_selection(self) -> None:
        selected = self.categories_table.selectedItems()
        if not selected:
            self._refresh_command_preview_page()
            return
        row = selected[0].row()
        preview = self.categories_table.item(row, 3).text()
        command_name = self.categories_table.item(row, 1).text()
        for command in self.registry.values():
            if command.name == command_name and self.runner.preview_command(command) == preview:
                details = self._render_command_details(command)
                self.command_preview.setPlainText(details)
                self.selected_command_panel.setPlainText(details)
                self.sidebar.setCurrentRow(6)
                break
        else:
            self._refresh_command_preview_page()

    def _default_command_preview_text(self) -> str:
        lines = [
            "Scope: audit and evidence-collection command previews only.",
            "",
            "This section answers: what commands can the audit engine run, what do they collect, what risk do they carry, and what failure modes should you expect?",
            "It does not list every possible remediation command. Remediation guidance appears in the side panel only after selecting a finding in Results.",
            "",
            "How to use it:",
            "1. Select a row in Scan Categories to inspect a specific command.",
            "2. Run a scan to generate real command/log activity.",
            "3. Review Raw Logs to compare planned commands with what actually ran.",
            "4. Select a finding in Results to review evidence, remediation steps, optional copyable commands, and verification steps.",
        ]
        if self.current_scan_result is not None and self.current_scan_result.raw_logs:
            lines.extend(["", "Recent command/log activity:"])
            lines.extend(
                f"- [{entry.collector_name}] {entry.command_or_source} exit={entry.exit_code if entry.exit_code is not None else 'n/a'}"
                for entry in self.current_scan_result.raw_logs[-8:]
                if entry.command_or_source
            )
        else:
            lines.extend(["", f"Registered commands available: {len(self.registry)}"])
        return "\n".join(lines)

    def _refresh_command_preview_page(self) -> None:
        if not hasattr(self, "command_preview"):
            return
        if hasattr(self, "categories_table") and self.categories_table.selectedItems():
            return
        self.command_preview.setPlainText(self._default_command_preview_text())

    def _update_selected_finding_panel(self) -> None:
        selected = self.findings_table.selectedItems()
        if not selected or not self.current_visible_findings:
            self._clear_selected_finding_panel()
            return
        row = selected[0].row()
        if row < 0 or row >= len(self.current_visible_findings):
            self._clear_selected_finding_panel()
            return
        finding = self.current_visible_findings[row]
        self.current_selected_finding = finding
        self.selected_command_panel.setPlainText(self._render_finding_details(finding))
        self.remediation_panel.setPlainText(self._render_remediation_details(finding))
        self.remediation_command_selector.clear()
        for command in finding.get("remediation_commands", []):
            self.remediation_command_selector.addItem(command)
            self.remediation_command_selector.setItemData(self.remediation_command_selector.count() - 1, command, Qt.ToolTipRole)
        has_commands = self.remediation_command_selector.count() > 0
        self.selected_finding_hint_label.setVisible(False)
        self.review_actions_frame.setVisible(True)
        self.remediation_actions_frame.setVisible(True)
        command_state = ActionState(
            enabled=has_commands,
            visible=True,
            reason="This finding does not include a copyable remediation command.",
            requirements=["finding with remediation command"],
        )
        apply_action_state(self.copy_command_button, command_state)
        apply_action_state(self.run_command_button, command_state)
        for name in [
            "add_finding_note_button",
            "mark_reviewed_button",
            "mark_false_positive_button",
            "mark_confirmed_button",
            "mark_follow_up_button",
            "show_context_button",
            "show_provenance_button",
        ]:
            widget = getattr(self, name, None)
            if widget is not None:
                apply_action_state(widget, ActionState(enabled=True, visible=True))

    def _change_findings_sort_order(self) -> None:
        if not hasattr(self, "findings_sort_combo"):
            return
        self.findings_sort_order = str(self.findings_sort_combo.currentData())
        if self.current_payload:
            self._populate_findings(normalize_findings(self.current_payload.get("findings", [])))

    def _apply_vulnerability_filters(self) -> None:
        if not self.current_payload:
            return
        self._populate_vulnerability_results(self.current_payload)

    def _sort_findings(self, findings: list[dict]) -> list[dict]:
        reverse = getattr(self, "findings_sort_order", "critical_to_low") != "low_to_critical"
        return sorted(
            findings,
            key=lambda finding: (
                SEVERITY_PRIORITY.get(str(finding.get("severity", "info")).lower(), 0),
                str(finding.get("category", "")),
                str(finding.get("title", "")),
            ),
            reverse=reverse,
        )

    def _clear_selected_finding_panel(self) -> None:
        self.current_selected_finding = None
        if hasattr(self, "selected_command_panel"):
            self.selected_command_panel.setPlainText(
                "No finding selected.\n\nSelect a finding in Results to see evidence, impact, false-positive notes, and references here. "
                "Select a Scan Categories row to see audit command metadata instead."
            )
        if hasattr(self, "remediation_panel"):
            self.remediation_panel.setPlainText(
                "No remediation item selected.\n\nRemediation guidance appears only for selected findings. "
                "Copyable commands are optional helper actions and may not be the full fix."
            )
        if hasattr(self, "remediation_command_selector"):
            self.remediation_command_selector.clear()
        if hasattr(self, "selected_finding_hint_label"):
            self.selected_finding_hint_label.setVisible(True)
        if hasattr(self, "review_actions_frame"):
            self.review_actions_frame.setVisible(False)
        if hasattr(self, "remediation_actions_frame"):
            self.remediation_actions_frame.setVisible(False)
        if hasattr(self, "copy_command_button"):
            apply_action_state(
                self.copy_command_button,
                ActionState(False, visible=True, reason="Select a finding with a remediation command first.", requirements=["selected finding"]),
            )
        if hasattr(self, "run_command_button"):
            apply_action_state(
                self.run_command_button,
                ActionState(False, visible=True, reason="Select a finding with a remediation command first.", requirements=["selected finding"]),
            )
        for name in [
            "add_finding_note_button",
            "mark_reviewed_button",
            "mark_false_positive_button",
            "mark_confirmed_button",
            "mark_follow_up_button",
            "show_context_button",
            "show_provenance_button",
        ]:
            widget = getattr(self, name, None)
            if widget is not None:
                apply_action_state(
                    widget,
                    ActionState(False, visible=False, reason="Select a finding first.", requirements=["selected finding"]),
                )

    def _render_command_details(self, command) -> str:
        return (
            "Audit Command Metadata\n"
            "This is a preview of a registered collection command. It is not remediation guidance.\n\n"
            f"Name: {command.name}\n"
            f"ID: {command.id}\n"
            f"Category: {command.category}\n"
            f"Risk: {command.risk_level}\n"
            f"Privilege required: {command.privilege_required}\n"
            f"Mutates system: {command.mutates_system}\n"
            f"Timeout: {command.timeout_seconds}s\n\n"
            f"Description:\n{command.description}\n\n"
            f"Command preview:\n{self.runner.preview_command(command)}\n\n"
            f"Collection warning:\n{command.collection_warning}\n\n"
            f"Failure modes:\n- " + "\n- ".join(command.failure_modes) + "\n\n"
            f"Disclaimer:\n{command.user_disclaimer}\n\n"
            f"Safer alternative:\n{command.safer_alternative}\n"
        )

    def _render_finding_details(self, finding: dict) -> str:
        guidance = self._remediation_guidance_for_finding(finding)
        text = (
            "Finding Evidence Details\n"
            "Use this section to understand what was observed before choosing any remediation.\n\n"
            f"Title: {finding.get('title', '')}\n"
            f"Severity: {finding.get('severity', 'info')}\n"
            f"Category: {finding.get('category', '')}\n"
            f"Evidence: {finding.get('evidence_summary', finding.get('evidence', ''))}\n\n"
            f"Why This Matters:\n{finding.get('why_this_matters') or guidance['why']}\n\n"
            f"False Positive Notes:\n{finding.get('false_positive_notes') or guidance['false_positive_notes']}\n"
        )
        if finding.get("privilege_escalation_context"):
            text += f"\nPrivilege Escalation:\n{finding.get('privilege_escalation_context', '')}\n"
        if finding.get("business_impact"):
            text += f"\nBusiness Impact:\n{finding.get('business_impact', '')}\n"
        if finding.get("local_network_impact"):
            text += f"\nLocal Network Impact:\n{finding.get('local_network_impact', '')}\n"
        references = finding.get("references", []) or finding.get("remediation_references", []) or []
        if references:
            text += "\nReferences:\n- " + "\n- ".join(str(reference) for reference in references)
        return text

    def _render_remediation_details(self, finding: dict) -> str:
        guidance = self._remediation_guidance_for_finding(finding)
        steps = finding.get("remediation_steps", []) or guidance["steps"]
        verification = finding.get("verification_steps", []) or guidance["verification"]
        references = finding.get("remediation_references", []) or []
        reversibility = "Reversible" if finding.get("reversible", True) else "Potentially hard to reverse"
        requires_admin = "Yes" if finding.get("requires_admin", False) else "No"
        text = (
            "Remediation Guidance\n"
            "These steps are selected-finding guidance. Any copyable commands below are optional helpers, not the only possible remediation path.\n\n"
            "What to do:\n- " + "\n- ".join(str(step) for step in steps) + "\n\n"
            f"Risk Level: {finding.get('remediation_risk', 'safe')}\n"
            f"Estimated Impact: {finding.get('estimated_impact', 'low')}\n"
            f"Requires Admin: {requires_admin}\n"
            f"Reversibility: {reversibility}\n\n"
            f"What Can Go Wrong:\n{finding.get('what_can_go_wrong') or guidance['what_can_go_wrong']}\n\n"
            f"Business Impact:\n{finding.get('business_impact') or guidance['business_impact']}\n\n"
            f"Local Network Impact:\n{finding.get('local_network_impact') or guidance['local_network_impact']}\n\n"
            f"Log Handling:\n{guidance['log_guidance']}\n\n"
            "Verification:\n- " + "\n- ".join(str(step) for step in verification)
        )
        if references:
            text += "\n\nReferences:\n- " + "\n- ".join(str(reference) for reference in references)
        return text

    def _remediation_guidance_for_finding(self, finding: dict) -> dict[str, object]:
        category = str(finding.get("category", "")).lower()
        title = str(finding.get("title", "")).lower()
        combined = f"{category} {title}"
        key = "default"
        for candidate in ["network", "persistence", "accounts", "files", "process", "vulnerability", "baseline", "monitor"]:
            if candidate in combined:
                key = candidate
                break
        if "user" in combined or "admin" in combined or "privilege" in combined:
            key = "accounts"
        if "cve" in combined or "apple security" in combined or "forecast" in combined:
            key = "vulnerability"
        template = DEFAULT_REMEDIATION_BY_CATEGORY[key]
        category_name = str(finding.get("category", "this category") or "this category")
        return {
            "steps": list(template["steps"]),
            "verification": list(template["verification"]),
            "why": f"This finding belongs to {category_name}; review the evidence in context before changing system state.",
            "false_positive_notes": "Confirm expected software, management tooling, updates, developer workflows, and user activity before treating this as malicious.",
            "what_can_go_wrong": "Acting too quickly can remove legitimate software, destroy evidence, interrupt services, or hide the sequence of events needed for remediation.",
            "business_impact": "Review whether the affected account, service, app, or network path supports normal work before changing it.",
            "local_network_impact": "Consider nearby shared services, credentials, VPNs, proxies, and remote access paths before blocking or removing components.",
            "log_guidance": self._log_guidance_for_finding_category(key),
        }

    def _log_guidance_for_finding_category(self, category_key: str) -> str:
        category_map = {
            "network": "Use Logs > Monitor Events and Scan Command Logs. Refresh before and after remediation; clear only the reviewed category after exporting evidence.",
            "persistence": "Use Logs > Scan Command Logs and Remediation Actions. Refresh after disabling or removing an item; preserve logs until persistence is verified gone.",
            "accounts": "Use Logs > Monitor Events and Remediation Actions. Refresh after account changes; clear only after exporting investigation records.",
            "files": "Use Logs > Scan Command Logs and Remediation Actions. Refresh file/process evidence before cleanup and keep logs until recovery is confirmed.",
            "process": "Use Logs > Monitor Events and Scan Command Logs. Refresh after stopping a process; preserve the process timeline first.",
            "vulnerability": "Use Logs > Scan Command Logs and Apple Security Forecast details. Refresh after updating; clear stale scan logs only after the fixed version is verified.",
            "baseline": "Use Logs > Scan Command Logs. Refresh baseline comparison after marking expected changes; clear only old scan logs after export.",
            "monitor": "Use Logs > Monitor Events and Application File Logs. Refresh after monitor repair; do not clear monitor events until alert flow is verified.",
        }
        return category_map.get(category_key, "Use Logs to refresh the relevant category before and after remediation; export evidence before clearing any category.")

    def _selected_remediation_command(self) -> str:
        if not hasattr(self, "remediation_command_selector") or self.remediation_command_selector.count() == 0:
            return ""
        return self.remediation_command_selector.currentText().strip()

    def copy_remediation_command(self) -> None:
        command_text = self._selected_remediation_command()
        finding = self.current_selected_finding
        if not command_text or not finding:
            QMessageBox.information(self, "No Command", "Select a finding with a remediation command first.")
            return
        QApplication.clipboard().setText(command_text)
        self._log_remediation_action(
            finding=finding,
            action_type="copy",
            command_text=command_text,
            explanation="Command copied to clipboard for manual review or execution.",
            user_approval=True,
            approval_text="COPY",
            result_text="copied to clipboard",
            exit_code=None,
        )
        self.statusBar().showMessage("remediation command copied", 5000)

    def run_remediation_command(self) -> None:
        command_text = self._selected_remediation_command()
        finding = self.current_selected_finding
        if not command_text or not finding:
            QMessageBox.information(self, "No Command", "Select a finding with a remediation command first.")
            return
        if shlex.split(command_text)[0] == "sudo":
            self._log_remediation_action(
                finding=finding,
                action_type="run_blocked",
                command_text=command_text,
                explanation="Automatic sudo escalation is not allowed for remediation commands.",
                user_approval=False,
                approval_text="BLOCKED_NO_SUDO",
                result_text="blocked because sudo is not permitted",
                exit_code=126,
            )
            QMessageBox.warning(self, "Command Blocked", "Remediation commands may not use sudo automatically.")
            return
        approved, approval_text = self._confirm_remediation_command(finding, command_text)
        if not approved:
            self._log_remediation_action(
                finding=finding,
                action_type="run_cancelled",
                command_text=command_text,
                explanation="User declined remediation command execution.",
                user_approval=False,
                approval_text=approval_text,
                result_text="user cancelled",
                exit_code=None,
            )
            return
        command = AuditCommand(
            id=f"remediation.{finding.get('id', 'unknown')}",
            name=f"Remediation: {finding.get('title', 'finding')}",
            description=finding.get("recommended_next_steps", "User-approved remediation command."),
            command=shlex.split(command_text),
            privilege_required=bool(finding.get("requires_admin", False)),
            risk_level=finding.get("remediation_risk", "safe"),
            mutates_system=True,
            timeout_seconds=30,
            collection_warning=finding.get("what_can_go_wrong", ""),
            failure_modes=["Command unavailable.", "Permission denied.", "Command failed."],
            user_disclaimer="User-approved remediation command. No automatic sudo escalation is applied.",
            safer_alternative="Copy the command and run it manually in Terminal after independent review.",
            category="Remediation",
        )
        self.db.record_user_approval(command.id, utc_now_iso(), approval_text)
        result = self.runner.execute(command, approval_token="RUN")
        self.db.record_command_log(self.current_scan_result.scan_id if self.current_scan_result else "ad-hoc", result)
        self._log_remediation_action(
            finding=finding,
            action_type="run",
            command_text=command_text,
            explanation=finding.get("recommended_next_steps", ""),
            user_approval=True,
            approval_text=approval_text,
            result_text=(result.stderr or result.stdout or "command completed").strip(),
            exit_code=result.exit_code,
        )
        if self.current_scan_result is not None:
            self.current_scan_result.raw_logs.append(
                RawLogEntry("remediation", command_text, result.executed_at, result.exit_code, result.stderr[:300], result.stdout[:500])
            )
        QMessageBox.information(
            self,
            "Remediation Command Result",
            f"Exit code: {result.exit_code}\n\nstdout:\n{result.stdout[:2000]}\n\nstderr:\n{result.stderr[:2000]}",
        )

    def _confirm_remediation_command(self, finding: dict, command_text: str) -> tuple[bool, str]:
        dialog = QDialog(self)
        dialog.setWindowTitle("Confirm Remediation Command")
        layout = QVBoxLayout(dialog)
        explanation = QTextEdit()
        explanation.setReadOnly(True)
        explanation.setPlainText(
            f"Exact command:\n{command_text}\n\n"
            f"Explanation:\n{finding.get('recommended_next_steps', '')}\n\n"
            f"Risk: {finding.get('remediation_risk', 'safe')}\n"
            f"What can go wrong:\n{finding.get('what_can_go_wrong', '')}"
        )
        confirm_checkbox = QCheckBox("I understand")
        typed_confirmation = QLineEdit()
        typed_confirmation.setPlaceholderText("Type RUN")
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(explanation)
        layout.addWidget(confirm_checkbox)
        layout.addWidget(typed_confirmation)
        layout.addWidget(buttons)
        approved = dialog.exec() == QDialog.DialogCode.Accepted and confirm_checkbox.isChecked() and typed_confirmation.text().strip() == "RUN"
        return approved, typed_confirmation.text().strip()

    def _log_remediation_action(
        self,
        *,
        finding: dict,
        action_type: str,
        command_text: str,
        explanation: str,
        user_approval: bool,
        approval_text: str,
        result_text: str,
        exit_code: int | None,
    ) -> None:
        created_at = utc_now_iso()
        self.db.record_remediation_action(
            scan_id=self.current_scan_result.scan_id if self.current_scan_result else "ad-hoc",
            finding_id=str(finding.get("id", "")),
            action_type=action_type,
            command_text=command_text,
            explanation=explanation,
            user_approval=user_approval,
            approval_text=approval_text,
            result_text=result_text,
            exit_code=exit_code,
            created_at=created_at,
        )

    def _refresh_dashboard(self) -> None:
        has_scan_result = self.current_scan_active and self.current_scan_result is not None
        export_state = ActionState(has_scan_result, True, "Run a scan first to generate an exportable report.", ["completed scan"])
        apply_action_state(self.export_json_button, export_state)
        apply_action_state(self.export_html_button, export_state)
        latest_scan = None
        findings = []
        if self.current_scan_active:
            latest_scan = self.current_scan_summary.to_dict() if self.current_scan_summary else self.db.latest_scan()
            findings = self.current_scan_result.findings if self.current_scan_result is not None else self.db.latest_findings()
        normalized_findings = normalize_findings(findings)
        if latest_scan:
            stored_score = latest_scan["security_score"]
            if stored_score is None or stored_score < 0:
                self.score_label.setText("Security Score: Unavailable")
            else:
                score_text = f"Security Score: {stored_score}/100"
                score_label = latest_scan.get("score_label") or self.collectors.score_label(stored_score)
                self.score_label.setText(f"{score_text} ({score_label})")
            self.summary_label.setText(
                f"Latest scan {latest_scan['completed_at']} with {latest_scan['findings_count']} findings and {latest_scan['new_items_count']} new items."
            )
        else:
            self.score_label.setText("Security Score: --")
            self.summary_label.setText("No active scan. Run a scan to begin.")
        if self.current_payload:
            mapping = {
                "Suspicious ports": self.current_payload["dashboard"]["suspicious_ports"],
                "Users/admin changes": self.current_payload["dashboard"]["users_admin_changes"],
                "Shell history indicators": self.current_payload["dashboard"]["history_indicators"],
                "Suspicious directories": self.current_payload["dashboard"]["suspicious_directories"],
                "New since last scan": self.current_payload["dashboard"]["new_since_last_scan"],
            }
            for label, value in mapping.items():
                self.dashboard_cards[label].setText(str(value))
            severity_source = normalize_findings(self.current_payload.get("findings", []))
        else:
            severity_source = normalized_findings
        severity_counts = {severity: 0 for severity in SEVERITY_COLOR_MAP}
        for finding in severity_source:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        for severity, value in severity_counts.items():
            self.severity_cards[severity].setText(str(value))
        self._populate_findings(normalized_findings if not self.current_payload else normalize_findings(self.current_payload.get("findings", [])))
        self._refresh_workflow_layer()

    def _load_scan_result(self, scan_result: ScanResult) -> None:
        self.current_scan_result = scan_result
        self.current_scan_active = True
        self._set_results_available(True)
        baseline = scan_result.baseline_diff
        ports = scan_result.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
        localhost_scan = scan_result.artifacts.get("localhost_scan", {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0})
        localhost_full_scan = scan_result.artifacts.get("localhost_full_port_scan", {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []})
        packet_captures = scan_result.artifacts.get("packet_captures", [])
        network_discovery = scan_result.artifacts.get("network_discovery", {"interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "host_count": 0, "review_needed_count": 0, "hosts": [], "devices": [], "comparison": {}, "debug_logs": [], "errors": []})
        processes = scan_result.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []})
        self.current_payload = {
            "findings": normalize_findings(scan_result.findings),
            "ports": ports,
            "localhost_scan": localhost_scan,
            "localhost_full_port_scan": localhost_full_scan,
            "packet_captures": packet_captures,
            "network_discovery": network_discovery,
            "catalog_status": {},
            "cve_findings": [],
            "best_practice_findings": [],
            "review_needed_findings": [],
            "processes": processes,
            "users": scan_result.artifacts.get("users", []),
            "history_indicators": scan_result.artifacts.get("history_indicators", []),
            "permission_snapshots": scan_result.artifacts.get("permission_snapshots", []),
            "file_issues": scan_result.artifacts.get("file_issues", []),
            "raw_logs": scan_result.raw_logs,
            "baseline_diff": baseline,
            "dashboard": {
                "suspicious_ports": len(ports.get("suspicious_review_needed", [])),
                "users_admin_changes": len(baseline.get("new_users", [])) + len(baseline.get("new_admin_users", [])),
                "history_indicators": len(scan_result.artifacts.get("history_indicators", [])),
                "suspicious_directories": len(scan_result.artifacts.get("file_issues", [])) + len(scan_result.artifacts.get("permission_snapshots", [])),
                "new_since_last_scan": sum(len(value) for value in baseline.values() if isinstance(value, list)),
                "baseline_drift_score": baseline.get("drift_score", 0),
                "baseline_drift_label": baseline.get("drift_label", "stable"),
            },
        }
        self._populate_scan_results(self.current_payload)
        self._refresh_workflow_layer()
        self.refresh_investigation_priorities()
        self.refresh_intrusion_detection()
        self.refresh_flight_recorder()
        self.refresh_logs_page()
        self.refresh_investigation_notes_page()
        self.refresh_operational_health()
        self.refresh_cve_radar(manual=False)
        self.refresh_system_recovery(manual=False)

    def _refresh_workflow_layer(self) -> None:
        if not hasattr(self, "workflow_replay_table"):
            return
        replay = self.workflow_layer.build_security_replay(limit=12, focus_scan_id=self.current_scan_result.scan_id if self.current_scan_result else None)
        queue = self.workflow_layer.build_review_queue(scan_id=self.current_scan_result.scan_id if self.current_scan_result else None)
        self._populate_table(
            self.workflow_replay_table,
            [[moment.timestamp, moment.moment_type, moment.title, moment.summary] for moment in replay],
        )
        self._populate_table(
            self.workflow_review_queue_table,
            [
                [
                    str(item.priority_score),
                    item.severity,
                    item.confidence,
                    item.review_state,
                    "yes" if item.suppressed else "no",
                    item.title,
                    item.explanation.get("next_action", ""),
                ]
                for item in queue
            ],
        )
        if self.workflow_review_queue_table.rowCount() > 0:
            self.workflow_review_queue_table.selectRow(0)
        self._refresh_workflow_explanation()

    def _refresh_workflow_explanation(self) -> None:
        if not hasattr(self, "workflow_explanation_table"):
            return
        if self.current_scan_result is None:
            self._populate_table(self.workflow_explanation_table, [["No scan selected", "Run or open a scan first."]])
            return
        queue = self.workflow_layer.build_review_queue(scan_id=self.current_scan_result.scan_id)
        row = self.workflow_review_queue_table.currentRow() if hasattr(self, "workflow_review_queue_table") else -1
        if row < 0 or row >= len(queue):
            if queue:
                row = 0
            else:
                self._populate_table(self.workflow_explanation_table, [["No review items", "No findings need workflow review yet."]])
                return
        item = queue[row]
        rows = [[key.replace("_", " ").title(), value] for key, value in item.explanation.items()]
        rows.insert(0, ["Priority Score", str(item.priority_score)])
        rows.insert(1, ["Severity", item.severity])
        rows.insert(2, ["Confidence", item.confidence])
        rows.insert(3, ["Review State", item.review_state])
        rows.insert(4, ["Suppressed", "yes" if item.suppressed else "no"])
        self._populate_table(self.workflow_explanation_table, rows)

    def refresh_investigation_priorities(self) -> None:
        if not hasattr(self, "investigation_priority_panel"):
            return
        try:
            report = self.investigation_priority_engine.build_priorities(scan_result=self.current_scan_result)
            report_dict = report.to_dict()
            self.investigation_priority_panel.set_report(report_dict)
            if hasattr(self, "investigation_priority_nav_panel"):
                self.investigation_priority_nav_panel.set_report(report_dict)
            if self.current_payload is not None:
                self.current_payload["investigation_priorities"] = report_dict
            if self.current_scan_result is not None:
                self.current_scan_result.collected_artifacts["investigation_priorities"] = report_dict
            LOGGER.info("Investigation Priorities rendered count=%s top3=%s", len(report.full_queue), len(report.top_3))
        except Exception as exc:
            LOGGER.exception("Failed to refresh Investigation Priorities: %s", exc)
            self.investigation_priority_panel.set_report(
                {
                    "generated_at": utc_now_iso(),
                    "scan_id": self.current_scan_result.scan_id if self.current_scan_result else "",
                    "summary": f"Unable to rank findings: {exc}",
                    "top_3": [],
                    "top_10": [],
                    "full_queue": [],
                    "counts": {"top_3": 0, "top_10": 0, "full_queue": 0},
                }
            )
            if hasattr(self, "investigation_priority_nav_panel"):
                self.investigation_priority_nav_panel.set_report(
                    {
                        "generated_at": utc_now_iso(),
                        "scan_id": self.current_scan_result.scan_id if self.current_scan_result else "",
                        "summary": f"Unable to rank findings: {exc}",
                        "top_3": [],
                        "top_10": [],
                        "full_queue": [],
                        "counts": {"top_3": 0, "top_10": 0, "full_queue": 0},
                    }
                )

    def refresh_intrusion_detection(self) -> None:
        if not hasattr(self, "intrusion_detection_panel"):
            return
        try:
            report = self.intrusion_correlation_engine.build_report(scan_result=self.current_scan_result)
            report_dict = report.to_dict()
            self.intrusion_detection_panel.set_report(report)
            if self.current_payload is not None:
                self.current_payload["intrusion_correlation"] = report_dict
            if self.current_scan_result is not None:
                self.current_scan_result.collected_artifacts["intrusion_correlation"] = report_dict
            LOGGER.info("Intrusion Detection rendered patterns=%s coverage=%s", len(report.patterns), report.coverage.score if report.coverage else 0)
        except Exception as exc:
            LOGGER.exception("Failed to refresh Intrusion Detection: %s", exc)
            self.intrusion_detection_panel.set_report(
                {
                    "generated_at": utc_now_iso(),
                    "scan_id": self.current_scan_result.scan_id if self.current_scan_result else "",
                    "summary": f"Unable to build intrusion correlation report: {exc}",
                    "patterns": [],
                    "top_patterns": [],
                    "user_presence": {"state": "unknown", "reason": "report unavailable", "confidence": "low"},
                    "coverage": {"score": 0, "summary": "Monitoring Coverage: 0%", "missing": [str(exc)]},
                    "recent_events": [item.to_dict() for item in self.db.recent_background_monitor_events(limit=50)],
                    "ai_summary": {},
                    "ai_summary_path": "",
                }
            )

    def refresh_flight_recorder(self) -> None:
        if not hasattr(self, "flight_recorder_panel"):
            return
        try:
            report = self.intrusion_correlation_engine.build_report(scan_result=self.current_scan_result)
            self.flight_recorder_panel.set_report(report)
        except Exception as exc:
            LOGGER.exception("Failed to refresh Flight Recorder: %s", exc)
            self.flight_recorder_panel.set_report(
                {
                    "generated_at": utc_now_iso(),
                    "scan_id": self.current_scan_result.scan_id if self.current_scan_result else "",
                    "summary": f"Unable to build flight recorder: {exc}",
                    "patterns": [],
                    "top_patterns": [],
                    "user_presence": {"state": "unknown", "reason": "report unavailable", "confidence": "low"},
                    "coverage": {"score": 0, "summary": "Monitoring Coverage: 0%"},
                    "recent_events": [],
                    "ai_summary": {},
                    "ai_summary_path": "",
                }
            )

    def refresh_logs_page(self) -> None:
        if not hasattr(self, "logs_panel"):
            return
        scan_logs = [entry.to_dict() for entry in self.current_scan_result.raw_logs[-200:]] if self.current_scan_result is not None else []
        events = [event.to_dict() for event in self.db.recent_background_monitor_events(limit=200)]
        snapshot = self.db.export_snapshot()
        command_logs = list(snapshot.get("command_logs", []))[:200]
        remediation_actions = list(snapshot.get("remediation_actions", []))[:200]
        app_file_logs = self._read_app_file_logs(limit=200)
        self.logs_panel.set_logs(
            {
                "summary": (
                    f"{len(events)} monitor events, {len(scan_logs) + len(command_logs)} scan command logs, "
                    f"{len(remediation_actions)} remediation actions, and {len(app_file_logs)} app log lines loaded locally."
                ),
                "events": events,
                "scan_logs": scan_logs,
                "command_logs": command_logs,
                "remediation_actions": remediation_actions,
                "app_file_logs": app_file_logs,
            }
        )

    def _read_app_file_logs(self, limit: int = 200) -> list[dict[str, str]]:
        path = self.db.logs_dir / "app.log"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        rows = []
        for line in lines:
            timestamp, _, message = line.partition(" ")
            rows.append({"timestamp": timestamp, "event_type": "app_log", "severity": "info", "message": message or line})
        return rows

    def clear_logs_category(self, category: str) -> None:
        if category == "all":
            QMessageBox.information(self, "Choose Log Category", "Choose a specific log category before clearing.")
            return
        if not self._confirm_clear_logs_category(category):
            return
        removed = 0
        try:
            if category == "monitor_events":
                removed = self.db.clear_monitor_events()
            elif category == "scan_command_logs":
                removed = self.db.clear_command_logs()
            elif category == "remediation_actions":
                removed = self.db.clear_remediation_actions()
            elif category == "app_file_logs":
                removed = self._clear_app_file_logs()
            else:
                QMessageBox.warning(self, "Unknown Log Category", f"Unknown log category: {category}")
                return
            self.statusBar().showMessage(f"cleared {removed} {category.replace('_', ' ')}", 5000)
            self.refresh_logs_page()
        except Exception as exc:
            QMessageBox.warning(self, "Clear Logs Failed", str(exc))

    def _confirm_clear_logs_category(self, category: str) -> bool:
        labels = {
            "monitor_events": "monitor events",
            "scan_command_logs": "scan command logs",
            "remediation_actions": "remediation action logs",
            "app_file_logs": "application file logs",
        }
        label = labels.get(category, category)
        message = (
            f"Clear {label}?\n\n"
            "This only clears the selected category. Export reports first if these logs are needed for investigation."
        )
        return QMessageBox.question(self, "Clear Log Category", message) == QMessageBox.StandardButton.Yes

    def _clear_app_file_logs(self) -> int:
        path = self.db.logs_dir / "app.log"
        existing = self._read_app_file_logs(limit=100000)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        return len(existing)

    def refresh_operational_health(self) -> None:
        if not hasattr(self, "operational_health_panel"):
            return
        try:
            report = self.operational_health_engine.build_report()
            self.operational_health_panel.set_report(report.to_dict())
            if hasattr(self, "dashboard_health_status_label"):
                self.dashboard_health_status_label.setText(f"Status: {report.overall_status}")
                self.dashboard_health_score_label.setText(f"Score: {report.health_score}/100")
                top_issue = next((check.summary for check in report.checks if check.status != "healthy"), "All core components are healthy.")
                self.dashboard_health_summary_label.setText(top_issue)
            if self.current_payload is not None:
                self.current_payload["operational_health"] = report.to_dict()
            LOGGER.info("Operational Health rendered status=%s score=%d", report.overall_status, report.health_score)
        except Exception as exc:
            LOGGER.exception("Failed to refresh Operational Health: %s", exc)
            if hasattr(self, "dashboard_health_status_label"):
                self.dashboard_health_status_label.setText("Status: broken")
                self.dashboard_health_score_label.setText("Score: 0/100")
                self.dashboard_health_summary_label.setText(str(exc))
            self.operational_health_panel.set_report(
                {
                    "generated_at": utc_now_iso(),
                    "overall_status": "broken",
                    "health_score": 0,
                    "checks": [
                        {
                            "component": "Operational Health",
                            "status": "broken",
                            "summary": f"Unable to build health report: {exc}",
                            "evidence": str(exc),
                            "next_step": "Open the logs and repair the failing component.",
                        }
                    ],
                    "details": {},
                }
            )

    def apply_theme_choice(self, theme_name: str, accessibility: bool) -> None:
        theme = theme_for_name(theme_name)
        self.db.set_background_monitor_state("selected_theme", theme.name)
        self.db.set_background_monitor_state("accessibility_high_contrast", "1" if accessibility else "0")
        self.setStyleSheet(theme_stylesheet(theme, accessibility_override=accessibility))
        if hasattr(self, "theme_panel"):
            self.theme_panel.set_theme(theme.name, accessibility)
        self.statusBar().showMessage(f"Theme applied: {theme.name}", 3000)

    def run_family_safety_audit(self, profile: str = "Shared Family Computer") -> None:
        try:
            self.family_safety_report = self.family_safety_auditor.build_report(profile)
        except Exception as exc:
            LOGGER.exception("Failed to run Family Safety audit: %s", exc)
            QMessageBox.warning(self, "Family Safety Audit Failed", str(exc))
            return
        self.family_safety_panel.set_report(self.family_safety_report.to_dict())
        self.statusBar().showMessage("Family Safety audit completed locally", 4000)

    def _current_family_safety_report(self):
        report = getattr(self, "family_safety_report", None)
        if report is None:
            self.run_family_safety_audit(self.family_safety_panel.profile_combo.currentText())
            report = getattr(self, "family_safety_report", None)
        return report

    def export_family_safety_html(self) -> None:
        report = self._current_family_safety_report()
        if report is None:
            return
        path = export_family_safety_html(report)
        QMessageBox.information(self, "Family Safety Report Exported", f"Local HTML report saved to:\n{path}")

    def export_family_safety_json(self) -> None:
        report = self._current_family_safety_report()
        if report is None:
            return
        path = export_family_safety_json(report)
        QMessageBox.information(self, "Family Safety Report Exported", f"Local JSON report saved to:\n{path}")

    def export_intrusion_ai_summary(self) -> None:
        try:
            report = self.intrusion_correlation_engine.build_report(scan_result=self.current_scan_result)
            path = self.intrusion_correlation_engine.write_ai_summary(report.ai_summary)
        except Exception as exc:
            LOGGER.exception("Failed to export AI summary: %s", exc)
            QMessageBox.warning(self, "Export AI Summary Failed", str(exc))
            return
        QMessageBox.information(self, "AI Summary Exported", f"Local AI-ready summary saved to:\n{path}")

    def _show_intrusion_context(self, item: object) -> None:
        payload = item.to_dict() if hasattr(item, "to_dict") else dict(item or {})
        if not isinstance(payload, dict):
            return
        window = self.intrusion_correlation_engine.build_context_window_for_event(payload)
        ContextDialog(window, self).exec()

    def _apply_cve_radar_payload(self, radar_payload: dict[str, object]) -> None:
        if self.current_payload is None:
            self.current_payload = {
                "findings": [],
                "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
                "localhost_scan": {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
                "localhost_full_port_scan": {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []},
                "packet_captures": [],
                "network_discovery": {"interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "host_count": 0, "review_needed_count": 0, "hosts": [], "devices": [], "comparison": {}, "debug_logs": [], "errors": []},
                "processes": {"all": [], "suspicious": [], "errors": []},
                "users": [],
                "history_indicators": [],
                "permission_snapshots": [],
                "file_issues": [],
                "raw_logs": [],
                "baseline_diff": {},
                "dashboard": {
                    "suspicious_ports": 0,
                    "users_admin_changes": 0,
                    "history_indicators": 0,
                    "suspicious_directories": 0,
                    "new_since_last_scan": 0,
                },
            }
        self.current_payload["apple_security_forecast"] = radar_payload
        self.current_payload["cve_radar"] = radar_payload
        if self.current_scan_result is not None:
            self.current_scan_result.collected_artifacts["apple_security_forecast"] = radar_payload
            self.current_scan_result.collected_artifacts["cve_radar"] = radar_payload
        if hasattr(self, "cve_radar_panel"):
            self.cve_radar_panel.set_radar_data(radar_payload)
            state_text = str(radar_payload.get("state_text", "") or radar_payload.get("level", radar_payload.get("forecast_level", "Forecast not checked yet")))
            self.cve_radar_panel.set_status(state_text)
        if hasattr(self, "dashboard_forecast_level_label"):
            level_text = str(radar_payload.get("state_text", radar_payload.get("level", "Forecast not checked yet")))
            self.dashboard_forecast_level_label.setText(f"Level: {level_text}")
            self.dashboard_forecast_last_checked_label.setText(f"Last checked: {radar_payload.get('generated_at', radar_payload.get('timestamp', 'not yet'))}")
            self.dashboard_forecast_cards_label.setText(f"Cards: {radar_payload.get('card_count', len(radar_payload.get('display_cards', radar_payload.get('cards', []))))}")
            self.dashboard_forecast_kev_label.setText(f"KEV: {radar_payload.get('kev_count', radar_payload.get('kev_matches', 0))}")
        LOGGER.info(
            "Apple Security Forecast rendered card_count=%d state=%s",
            len(radar_payload.get("display_cards", radar_payload.get("cards", []))),
            radar_payload.get("state_text", radar_payload.get("level", "")),
        )

    def refresh_apple_security_forecast(
        self,
        manual: bool = False,
        force: bool = False,
        *,
        initial_load: bool = False,
    ) -> None:
        if not hasattr(self, "cve_radar_panel"):
            return
        if initial_load and not manual and not force and not self.config.auto_update_apple_security_forecast:
            LOGGER.info("Apple Security Forecast initial load from cache only")
            cached = self.cve_radar_engine.load_cached_state()
            self._apply_cve_radar_payload(cached)
            self.statusBar().showMessage("Apple Security Forecast loaded from cache", 3000)
            return
        if not manual and not force and not self.config.auto_update_apple_security_forecast:
            cached = self.cve_radar_engine.load_cached_state()
            self._apply_cve_radar_payload(cached)
            self.cve_radar_panel.set_status(str(cached.get("state_text", "Forecast not checked yet")))
            return
        self.cve_radar_panel.set_status("Checking Apple Security Forecast...")
        try:
            radar_payload = self.cve_radar_engine.update_radar(
                current_scan_result=self.current_scan_result,
                manual=manual,
                force=force,
            )
        except Exception as exc:
            LOGGER.exception("Failed to refresh Apple Security Forecast: %s", exc)
            self.statusBar().showMessage("Apple Security Forecast update failed", 5000)
            cached = self.cve_radar_engine.load_cached_state()
            if not cached.get("timestamp") and not cached.get("display_cards"):
                cached["state_text"] = "Unable to update forecast — no cache available"
                cached["why_no_cards"] = str(exc)
            else:
                cached["state_text"] = "Unable to update forecast — using cache"
                cached["why_no_cards"] = str(exc)
            self._apply_cve_radar_payload(cached)
            self.cve_radar_panel.set_status(str(cached.get("state_text", "Unable to update forecast — using cache")))
            return
        self._apply_cve_radar_payload(radar_payload)
        LOGGER.info(
            "Apple Security Forecast rendered state=%s cards=%d",
            radar_payload.get("state_text", radar_payload.get("level", "")),
            len(radar_payload.get("display_cards", radar_payload.get("cards", []))),
        )
        self.statusBar().showMessage("Apple Security Forecast updated", 3000)

    def refresh_cve_radar(self, manual: bool = False, force: bool = False) -> None:
        self.refresh_apple_security_forecast(manual=manual, force=force)

    def _recovery_extra_specs(self) -> list[dict[str, object]]:
        specs: list[dict[str, object]] = []
        if not hasattr(self, "system_recovery_panel"):
            return specs
        for raw_path in self.system_recovery_panel.extra_cleanup_roots():
            try:
                path = Path(raw_path).expanduser()
            except Exception:
                continue
            if not str(path).strip():
                continue
            specs.append(
                {
                    "category": "review",
                    "kind": "user-selected log folder",
                    "path": path,
                    "risk": "medium",
                }
            )
        return specs

    def refresh_system_recovery(self, manual: bool = False, *, initial_load: bool = False, preview_only: bool = False) -> None:
        if not hasattr(self, "system_recovery_panel"):
            return
        try:
            context = self.recovery_center.build_context(self.current_scan_result, self.current_payload)
            if preview_only or manual or initial_load:
                preview = self.recovery_center.build_cleanup_preview(
                    self.current_scan_result,
                    self.current_payload,
                    extra_roots=self._recovery_extra_specs() or None,
                )
                context["preview"] = preview.to_dict()
                context["assessment"] = self.recovery_center.incident_awareness_check(self.current_scan_result, self.current_payload).to_dict()
                context["snapshot_history"] = self.db.list_system_recovery_snapshots(limit=20)
                context["cleanup_history"] = self.db.list_system_cleanup_actions(limit=20)
                context["generated_at"] = preview.generated_at
            self.system_recovery_panel.set_recovery_data(context)
            LOGGER.info(
                "System Recovery rendered state=%s score=%s opportunities=%s",
                context.get("assessment", {}).get("title", ""),
                context.get("preview", {}).get("recovery_score", 0),
                context.get("preview", {}).get("opportunities", 0),
            )
        except Exception as exc:
            LOGGER.exception("Failed to refresh System Recovery: %s", exc)
            degraded = {
                "assessment": {
                    "title": "Unable to update recovery center",
                    "level": "safe",
                    "reasons": [str(exc)],
                    "recommendation": "Review logs and try again.",
                },
                "preview": {
                    "generated_at": "",
                    "summary": "No recovery preview available.",
                    "recovery_score": 0,
                    "opportunities": 0,
                    "total_recoverable_bytes": 0,
                    "performance_improvement": "Low",
                    "risk_level": "safe",
                    "candidates": [],
                    "growth_summary": [],
                    "protected_paths": [],
                },
                "snapshot_history": self.db.list_system_recovery_snapshots(limit=20),
                "cleanup_history": self.db.list_system_cleanup_actions(limit=20),
                "cache_age": "unknown",
                "generated_at": "",
                "last_error": str(exc),
            }
            self.system_recovery_panel.set_recovery_data(degraded)

    def run_system_recovery_incident_check(self) -> None:
        self.refresh_system_recovery(manual=True)
        assessment = self.recovery_center.incident_awareness_check(self.current_scan_result, self.current_payload)
        QMessageBox.information(self, "Incident Awareness Check", f"{assessment.title}\n\n" + "\n".join(f"- {reason}" for reason in assessment.reasons))

    def create_system_recovery_snapshot(self) -> None:
        try:
            assessment = self.recovery_center.incident_awareness_check(self.current_scan_result, self.current_payload)
            preview = self.recovery_center.build_cleanup_preview(
                self.current_scan_result,
                self.current_payload,
                extra_roots=self._recovery_extra_specs() or None,
            )
            snapshot = self.recovery_center.create_evidence_snapshot(self.current_scan_result, self.current_payload, assessment, preview, reason="manual")
            self.statusBar().showMessage("System recovery snapshot created", 5000)
            QMessageBox.information(self, "Evidence Snapshot Created", f"Snapshot created before cleanup:\n{snapshot['snapshot_path']}")
        except Exception as exc:
            LOGGER.exception("Failed to create system recovery snapshot: %s", exc)
            QMessageBox.warning(self, "Snapshot Failed", f"Unable to create an evidence snapshot:\n{exc}")
        finally:
            self.refresh_system_recovery(manual=True)

    def preview_system_recovery_cleanup(self) -> None:
        self.refresh_system_recovery(manual=True, preview_only=True)
        if hasattr(self, "system_recovery_panel"):
            self.system_recovery_panel.tabs.setCurrentIndex(1)
        self.statusBar().showMessage("System recovery preview updated", 3000)

    def run_system_recovery_cleanup(self) -> None:
        if not hasattr(self, "system_recovery_panel"):
            return
        warning_dialog = RecoveryEvidenceWarningDialog(self)
        result = warning_dialog.exec()
        choice = warning_dialog.choice() if result == QDialog.Accepted else "cancel"
        if choice == "cancel":
            self.statusBar().showMessage("System recovery cleanup cancelled", 3000)
            return
        assessment = self.recovery_center.incident_awareness_check(self.current_scan_result, self.current_payload)
        preview = self.recovery_center.build_cleanup_preview(
            self.current_scan_result,
            self.current_payload,
            extra_roots=self._recovery_extra_specs() or None,
        )
        if choice == "snapshot":
            self.recovery_center.create_evidence_snapshot(self.current_scan_result, self.current_payload, assessment, preview, reason="cleanup")
            self.statusBar().showMessage("Evidence snapshot created before cleanup", 4000)
            self.refresh_system_recovery(manual=True)
            return
        selected_paths = self.system_recovery_panel.selected_cleanup_paths()
        if not selected_paths:
            QMessageBox.information(self, "No Cleanup Selection", "Select one or more cleanup candidates in the Cleanup tab before running cleanup.")
            return
        try:
            result_payload = self.recovery_center.run_cleanup(
                selected_paths,
                self.current_scan_result,
                self.current_payload,
                create_snapshot_first=False,
                preview=preview,
                assessment=assessment,
            )
            deleted_count = len(result_payload.get("deleted", []))
            self.statusBar().showMessage(f"System recovery cleanup completed: {deleted_count} items", 5000)
            QMessageBox.information(self, "Cleanup Complete", str(result_payload.get("result_text", "Cleanup complete.")))
        except Exception as exc:
            LOGGER.exception("System recovery cleanup failed: %s", exc)
            QMessageBox.warning(self, "Cleanup Failed", f"Cleanup could not be completed safely:\n{exc}")
        finally:
            self.refresh_system_recovery(manual=True)

    def open_system_recovery_snapshots_folder(self) -> None:
        snapshot_dir = Path(getattr(self.config, "recovery_snapshot_dir", Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "snapshots")).expanduser()
        try:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["open", str(snapshot_dir)], check=False)
        except Exception as exc:
            QMessageBox.warning(self, "Open Snapshots Folder Failed", f"Failed to open snapshots folder:\n{snapshot_dir}\n\n{exc}")
            return
        QMessageBox.information(self, "Open Snapshots Folder", f"Snapshots folder opened:\n{snapshot_dir}")

    def show_apple_security_forecast_diagnostics(self) -> None:
        diagnostics = self.cve_radar_engine.diagnostics_snapshot()
        lines = [
            "Safari Private Browsing does not affect this forecast. The forecast uses installed Safari/macOS version and Apple advisory/update data only.",
            "",
            f"Last update time: {diagnostics.get('last_update_time', 'not yet')}",
            f"Last successful update time: {diagnostics.get('last_successful_update_time', 'not yet')}",
            f"Cache age: {diagnostics.get('cache_age', 'unknown')}",
            f"Apple source status: {diagnostics.get('apple_source_status', 'cache')}",
            f"KEV source status: {diagnostics.get('kev_source_status', 'cache')}",
            f"NVD enrichment status: {diagnostics.get('nvd_source_status', 'cache')}",
            f"EPSS source status: {diagnostics.get('epss_source_status', 'cache')}",
            f"macOS version/build: {diagnostics.get('inventory', {}).get('macos_version', '')} {diagnostics.get('inventory', {}).get('macos_build', '')}".strip(),
            f"Safari version: {diagnostics.get('inventory', {}).get('safari_version', '')}",
            f"Safari build: {diagnostics.get('inventory', {}).get('safari_build', '')}",
            f"Safari detection method: {diagnostics.get('inventory', {}).get('safari_detection_method', '')}",
            f"WebKit version: {diagnostics.get('inventory', {}).get('webkit_version', '')}",
            f"Xcode version: {diagnostics.get('inventory', {}).get('xcode_version', '')}",
            f"CLT version: {diagnostics.get('inventory', {}).get('command_line_tools_version', '')}",
            f"Architecture: {diagnostics.get('inventory', {}).get('architecture', '')}",
            f"Model identifier: {diagnostics.get('inventory', {}).get('device_model', '')}",
            f"Software update check status: {diagnostics.get('inventory', {}).get('software_update_check_status', '')}",
            f"Advisories downloaded: {diagnostics.get('advisories_downloaded', 0)}",
            f"Advisories parsed: {diagnostics.get('advisories_parsed', 0)}",
            f"Advisories within 90 days: {diagnostics.get('advisories_within_90_days', 0)}",
            f"Invalid advisories: {diagnostics.get('invalid_advisories', 0)}",
            f"Filtered advisories: {diagnostics.get('filtered_advisories', 0)}",
            f"Historical advisories: {diagnostics.get('historical_advisories', 0)}",
            f"Stale advisories hidden: {diagnostics.get('stale_advisories', 0)}",
            f"Non-Mac advisories hidden: {diagnostics.get('non_mac_advisories_hidden', 0)}",
            f"Review-needed hidden: {diagnostics.get('review_needed_hidden', 0)}",
            f"Applicable advisories: {diagnostics.get('applicable_advisories', 0)}",
            f"Cards generated: {diagnostics.get('cards_generated_count', 0)}",
            f"Filtered non-Apple CVEs: {diagnostics.get('filtered_non_apple_cves_count', 0)}",
            f"Hidden review-needed: {diagnostics.get('hidden_review_needed_count', 0)}",
            f"Why no cards were shown: {diagnostics.get('why_no_cards', '') or 'not applicable'}",
            f"Last error: {diagnostics.get('last_error', 'none') or 'none'}",
            "SQLite table counts:",
            f"  apple_security_forecasts: {diagnostics.get('table_counts', {}).get('apple_security_forecasts', 0)}",
            f"  apple_security_forecast_cards: {diagnostics.get('table_counts', {}).get('apple_security_forecast_cards', 0)}",
            f"  apple_security_cve_cache: {diagnostics.get('table_counts', {}).get('apple_security_cve_cache', 0)}",
            f"  apple_security_review_state: {diagnostics.get('table_counts', {}).get('apple_security_review_state', 0)}",
        ]
        dialog = CveRadarDetailsDialog("Forecast Diagnostics", "\n".join(lines), self)
        dialog.exec()

    def _review_cve_radar_card(self, card: dict[str, object]) -> None:
        alert_ids = [str(item.get("alert_id", "")) for item in card.get("alerts", [card]) if isinstance(item, dict) and item.get("alert_id")]
        if not alert_ids:
            return
        for alert_id in alert_ids:
            self.cve_radar_engine.mark_reviewed(alert_id, notes="Marked reviewed from radar panel.")
        self._apply_cve_radar_payload(self.cve_radar_engine.load_cached_state())
        self.statusBar().showMessage("Apple Security Forecast item marked reviewed", 3000)

    def _snooze_cve_radar_card(self, card: dict[str, object], values: dict[str, object]) -> None:
        alert_ids = [str(item.get("alert_id", "")) for item in card.get("alerts", [card]) if isinstance(item, dict) and item.get("alert_id")]
        if not alert_ids:
            return
        days = values.get("days")
        until_next_version_change = bool(values.get("until_next_version_change"))
        for alert_id in alert_ids:
            self.cve_radar_engine.snooze(
                alert_id,
                days=int(days) if isinstance(days, int) else None,
                until_next_version_change=until_next_version_change,
                notes="Snoozed from radar panel.",
            )
        self._apply_cve_radar_payload(self.cve_radar_engine.load_cached_state())
        self.statusBar().showMessage("Apple Security Forecast item snoozed", 3000)

    def _change_page(self, row: int) -> None:
        if row >= 0 and hasattr(self, "pages"):
            self.pages.setCurrentIndex(row)
            current_item = self.sidebar.item(row) if hasattr(self, "sidebar") else None
            current_text = current_item.text() if current_item is not None else ""
            if current_text == "Investigation Priorities" and hasattr(self, "results_tabs"):
                self.results_tabs.setCurrentWidget(self.investigation_priority_panel)
            elif current_text == "Results" and hasattr(self, "results_tabs"):
                self.results_tabs.setCurrentIndex(0)

    def _show_sidebar_page(self, title: str) -> None:
        if not hasattr(self, "sidebar"):
            return
        matches = self.sidebar.findItems(title, Qt.MatchExactly)
        if matches:
            self.sidebar.setCurrentItem(matches[0])

    def show_forecast_page(self) -> None:
        self._show_sidebar_page("Dashboard")
        if hasattr(self, "cve_radar_panel"):
            self.cve_radar_panel.setFocus(Qt.OtherFocusReason)
        self.statusBar().showMessage("Apple Security Forecast is available on the Dashboard", 3000)

    def show_intrusion_detection_page(self) -> None:
        self._show_sidebar_page("Intrusion Detection")

    def show_investigation_priorities_page(self) -> None:
        self._show_sidebar_page("Investigation Priorities")

    def show_flight_recorder_page(self) -> None:
        self._show_sidebar_page("Flight Recorder")

    def show_system_recovery_page(self) -> None:
        self._show_sidebar_page("Evidence Snapshots")

    def show_logs_page(self) -> None:
        self._show_sidebar_page("Logs")

    def show_settings_page(self) -> None:
        self._show_sidebar_page("Settings")

    def show_skins_page(self) -> None:
        self._show_sidebar_page("Skins")

    def show_family_safety_page(self) -> None:
        self._show_sidebar_page("Family & Safety")

    def show_background_monitor_page(self) -> None:
        self.show_settings_page()

    def trigger_background_monitor_test_event(self) -> None:
        self.show_background_monitor_page()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.generate_test_event()

    def trigger_background_monitor_test_notification(self) -> None:
        self.show_background_monitor_page()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.test_notification()

    def trigger_background_monitor_test_dialog(self) -> None:
        self.show_background_monitor_page()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.test_high_priority_dialog()

    def trigger_background_monitor_test_overlay(self) -> None:
        self.show_background_monitor_page()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.test_bottom_right_alert()

    def trigger_background_monitor_test_idle_warning(self) -> None:
        self.show_background_monitor_page()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.test_idle_activity_warning()

    def run_scan(self) -> None:
        self.statusBar().showMessage("scan started")
        scan_mode = self.scan_mode_combo.currentData()
        localhost_protocol = self.localhost_protocol_combo.currentData()
        if self.config.fresh_baseline_validation_mode or self.config.uat_live_environment_mode:
            scan_mode = "safe"
            localhost_protocol = "tcp"
        response = QMessageBox.question(
            self,
            "Shell History Privacy Warning",
            "This scan reviews shell history for suspicious indicators only. It does not store full history by default. Continue?",
        )
        if response != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("scan cancelled", 3000)
            return
        if scan_mode == "aggressive":
            warning = (
                "This scans TCP and/or UDP ports on 127.0.0.1 only. It may trigger local security tools or create noisy logs. "
                "It does not scan your network."
            )
            confirm = QMessageBox.question(self, "Aggressive Local Scan", warning)
            if confirm != QMessageBox.StandardButton.Yes:
                self.statusBar().showMessage("aggressive local scan cancelled", 3000)
                return

        self.db.prune_old_logs()
        previous_scan_result = self.db.latest_scan_result()
        started_at = utc_now_iso()

        phases = [
            "Preparing the read-only scan plan and loading the previous baseline.",
            "Collecting process, network, account, permission, and persistence evidence.",
            "Running local-only command previews and bounded artifact checks.",
            "Comparing current evidence with the stored baseline.",
            "Scoring findings and preparing the report view.",
        ]
        progress_dialog = GuidedLongActionDialog("Scan Running", phases, self)

        def _scan_action(progress: Callable[[dict], None]) -> ScanResult:
            progress({"message": phases[0], "completed": 0, "total": len(phases)})
            progress({"message": phases[1], "completed": 1, "total": len(phases)})
            result = self.collectors.run_scan(
                previous_result=previous_scan_result,
                scan_mode=scan_mode,
                localhost_scan_protocol=localhost_protocol,
            )
            progress({"message": phases[4], "completed": len(phases) - 1, "total": len(phases)})
            return result

        self.statusBar().showMessage("collector running")
        progress_dialog.start_action(_scan_action)
        if progress_dialog.exec() != QDialog.Accepted or not isinstance(progress_dialog.result_data, ScanResult):
            self.statusBar().showMessage("scan failed", 5000)
            if progress_dialog.error:
                QMessageBox.warning(self, "Scan Failed", progress_dialog.error)
            return
        scan_result = progress_dialog.result_data
        self._persist_completed_scan(
            scan_result=scan_result,
            started_at=started_at,
            scan_mode=str(scan_mode),
            localhost_protocol=str(localhost_protocol),
        )

    def _persist_completed_scan(self, *, scan_result: ScanResult, started_at: str, scan_mode: str, localhost_protocol: str) -> None:
        self.statusBar().showMessage("collector completed")
        completed_at = utc_now_iso()
        score = self.collectors.compute_security_score(scan_result.findings)
        score_label = self.collectors.score_label(score)
        summary = ScanSummary(
            scan_id=scan_result.scan_id,
            started_at=started_at,
            completed_at=completed_at,
            findings_count=len(scan_result.findings),
            security_score=score,
            notes="Safe, read-only macOS audit with redacted history indicators and targeted snapshot comparison.",
            new_items_count=sum(len(value) for value in scan_result.baseline_diff.values() if isinstance(value, list)),
            score_label=score_label,
        )
        self.db.record_scan(summary)
        self.db.record_scan_result(scan_result)
        for result in scan_result.artifacts.get("command_results", []):
            self.db.record_command_log(scan_result.scan_id, result)
        for finding in scan_result.findings:
            self.db.record_finding(scan_result.scan_id, finding)
        self.db.record_snapshots(
            scan_result.scan_id,
            ports=scan_result.artifacts.get("ports", {}).get("listening", []),
            users=scan_result.artifacts.get("users", []),
            history_indicators=scan_result.artifacts.get("history_indicators", []),
            permissions=scan_result.artifacts.get("permission_snapshots", []),
            files=scan_result.artifacts.get("file_issues", []),
            processes=scan_result.artifacts.get("processes", {}).get("all", []),
            launch_snapshots=scan_result.artifacts.get("launch_snapshots", []),
            launch_items=set(scan_result.artifacts.get("launch_items", [])),
        )
        self.db.write_scan_logs(scan_result.scan_id, {
            "findings": scan_result.findings,
            "command_results": scan_result.artifacts.get("command_results", []),
            "ports": scan_result.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}),
            "localhost_scan": scan_result.artifacts.get("localhost_scan", {"target": "127.0.0.1", "mode": scan_mode, "protocol": localhost_protocol, "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0}),
            "processes": scan_result.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []}),
            "users": scan_result.artifacts.get("users", []),
            "history_indicators": scan_result.artifacts.get("history_indicators", []),
            "permission_snapshots": scan_result.artifacts.get("permission_snapshots", []),
            "file_issues": scan_result.artifacts.get("file_issues", []),
            "launch_snapshots": scan_result.artifacts.get("launch_snapshots", []),
            "comparison": type("BaselineHolder", (), {"to_dict": lambda self_: scan_result.baseline_diff})(),
            "raw_logs": scan_result.raw_logs,
        })
        self.current_scan_summary = summary
        self._load_scan_result(scan_result)
        self._refresh_dashboard()
        self._refresh_command_preview_page()
        self.statusBar().showMessage("scan completed", 5000)
        QMessageBox.information(self, "Scan Complete", f"Scan finished with {len(scan_result.findings)} findings.")

    def run_aggressive_local_vulnerability_review(self) -> None:
        if self.config.fresh_baseline_validation_mode or self.config.uat_live_environment_mode or self.config.disable_aggressive_scan:
            QMessageBox.information(self, "Disabled", "Aggressive local vulnerability review is disabled in the current mode.")
            return
        warning = (
            "This performs a local-only vulnerability and best-practice review using cached or freshly updated catalogs, "
            "local software inventory, and localhost artifacts. It does not exploit targets or scan remote hosts."
        )
        confirm = QMessageBox.question(self, "Aggressive Local Vulnerability Review", warning)
        if confirm != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("aggressive local vulnerability review cancelled", 3000)
            return
        self.statusBar().showMessage("aggressive local vulnerability review running")
        phases = [
            "Preparing local vulnerability catalogs and scan context.",
            "Collecting a supporting safe scan if no scan is loaded.",
            "Reviewing local software, localhost evidence, and best-practice posture.",
            "Separating confirmed findings from review-needed items.",
            "Preparing vulnerability results for display.",
        ]
        progress_dialog = GuidedLongActionDialog("Aggressive Local Vulnerability Review", phases, self)

        def _review_action(progress: Callable[[dict], None]) -> tuple[ScanResult, dict]:
            progress({"message": phases[0], "completed": 0, "total": len(phases)})
            supporting_scan = self.current_scan_result
            if supporting_scan is None:
                progress({"message": phases[1], "completed": 1, "total": len(phases)})
                supporting_scan = self.collectors.run_scan(scan_mode="safe", localhost_scan_protocol="both")
            localhost_full_scan = supporting_scan.artifacts.get("localhost_full_port_scan")
            progress({"message": phases[2], "completed": 2, "total": len(phases)})
            review = self.vulnerability_reviewer.review(
                current_findings=supporting_scan.findings,
                localhost_full_scan=localhost_full_scan,
            )
            progress({"message": phases[4], "completed": len(phases) - 1, "total": len(phases)})
            return supporting_scan, review

        progress_dialog.start_action(_review_action)
        if progress_dialog.exec() != QDialog.Accepted or not isinstance(progress_dialog.result_data, tuple):
            self.statusBar().showMessage("aggressive local vulnerability review failed", 5000)
            if progress_dialog.error:
                QMessageBox.warning(self, "Aggressive Review Failed", progress_dialog.error)
            return
        supporting_scan, review = progress_dialog.result_data
        self.current_scan_result = supporting_scan
        self.current_scan_active = True
        supporting_scan.collected_artifacts["catalog_status"] = review["catalog_update_status"]
        supporting_scan.collected_artifacts["cve_findings"] = review["cve_findings"]
        supporting_scan.collected_artifacts["best_practice_findings"] = review["best_practice_findings"]
        supporting_scan.collected_artifacts["review_needed_findings"] = review["review_needed_findings"]
        supporting_scan.collected_artifacts["vulnerability_review_stats"] = review["stats"]
        supporting_scan.collected_artifacts["patch_posture"] = review.get("patch_posture", {})
        if self.current_payload is None:
            self.current_payload = {
                "findings": normalize_findings(supporting_scan.findings),
                "ports": supporting_scan.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}),
                "localhost_scan": supporting_scan.artifacts.get("localhost_scan", {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0}),
                "localhost_full_port_scan": supporting_scan.artifacts.get("localhost_full_port_scan", {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []}),
                "processes": supporting_scan.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []}),
                "users": supporting_scan.artifacts.get("users", []),
                "history_indicators": supporting_scan.artifacts.get("history_indicators", []),
                "permission_snapshots": supporting_scan.artifacts.get("permission_snapshots", []),
                "file_issues": supporting_scan.artifacts.get("file_issues", []),
                "raw_logs": supporting_scan.raw_logs,
                "baseline_diff": supporting_scan.baseline_diff,
                "dashboard": self.collectors._dashboard_summary(supporting_scan),
            }
        self.current_payload["catalog_status"] = review["catalog_update_status"]
        self.current_payload["cve_findings"] = review["cve_findings"]
        self.current_payload["best_practice_findings"] = review["best_practice_findings"]
        self.current_payload["review_needed_findings"] = review["review_needed_findings"]
        self.current_payload["vulnerability_review_stats"] = review["stats"]
        self.current_payload["patch_posture"] = review.get("patch_posture", {})
        self.background_monitor_panel.notifications.notify_findings_digest(review["cve_findings"])
        self._populate_scan_results(self.current_payload)
        self.results_tabs.setCurrentWidget(self.catalog_status_table)
        self._refresh_command_preview_page()
        self.statusBar().showMessage("aggressive local vulnerability review completed", 5000)

    def run_full_localhost_port_scan(self) -> None:
        if self.config.fresh_baseline_validation_mode or self.config.uat_live_environment_mode or self.config.disable_aggressive_scan:
            QMessageBox.information(self, "Disabled", "Full localhost port scan is disabled in the current mode.")
            return
        warning = (
            "This scans TCP and UDP ports 1-65535 on 127.0.0.1 only and performs passive TCP banner grabbing. "
            "It may take time, trigger local security tools, or create noisy logs. "
            "It does not scan your network."
        )
        confirm = QMessageBox.question(self, "Full Localhost Port Scan", warning)
        if confirm != QMessageBox.StandardButton.Yes:
            self.statusBar().showMessage("full localhost port scan cancelled", 3000)
            return
        self.statusBar().showMessage("full localhost port scan running")
        phases = [
            "Preparing local-only TCP and UDP localhost scan.",
            "Scanning 127.0.0.1 ports without touching remote network hosts.",
            "Collecting passive TCP banners where available.",
            "Summarizing responsive and unknown UDP results.",
            "Preparing localhost scan results for display.",
        ]
        progress_dialog = GuidedLongActionDialog("Full Localhost Port Scan", phases, self)

        def _localhost_action(progress: Callable[[dict], None]) -> dict:
            progress({"message": phases[0], "completed": 0, "total": len(phases)})
            progress({"message": phases[1], "completed": 1, "total": len(phases)})
            artifact = self.collectors.collect_full_localhost_port_scan()
            progress({"message": phases[4], "completed": len(phases) - 1, "total": len(phases)})
            return artifact

        progress_dialog.start_action(_localhost_action)
        if progress_dialog.exec() != QDialog.Accepted or not isinstance(progress_dialog.result_data, dict):
            self.statusBar().showMessage("full localhost port scan failed", 5000)
            if progress_dialog.error:
                QMessageBox.warning(self, "Full Localhost Port Scan Failed", progress_dialog.error)
            return
        artifact = progress_dialog.result_data
        if self.current_payload is None:
            self.current_payload = {
                "findings": [],
                "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
                "localhost_scan": {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
                "localhost_full_port_scan": artifact,
                "processes": {"all": [], "suspicious": [], "errors": []},
                "users": [],
                "history_indicators": [],
                "permission_snapshots": [],
                "file_issues": [],
                "raw_logs": [],
                "baseline_diff": {},
                "dashboard": {
                    "suspicious_ports": 0,
                    "users_admin_changes": 0,
                    "history_indicators": 0,
                    "suspicious_directories": 0,
                    "new_since_last_scan": 0,
                },
            }
        else:
            self.current_payload["localhost_full_port_scan"] = artifact
        if self.current_scan_result is not None:
            self.current_scan_result.collected_artifacts["localhost_full_port_scan"] = artifact
            self.current_scan_result.raw_logs.append(
                RawLogEntry(
                    "localhost_full_port_scan",
                    "127.0.0.1 tcp/udp 1-65535",
                    utc_now_iso(),
                    0,
                    "; ".join(str(item) for item in artifact.get("errors", []))[:300],
                    f"tcp_open={len(artifact.get('tcp_open_ports', []))} tcp_banners={len(artifact.get('tcp_banners', {}))} udp_unknown={len(artifact.get('udp_responsive_or_unknown_ports', []))}",
                )
            )
        self._populate_scan_results(self.current_payload)
        self.results_tabs.setCurrentWidget(self.localhost_full_scan_table)
        self._refresh_command_preview_page()
        self.statusBar().showMessage("full localhost port scan completed", 5000)
        QMessageBox.information(
            self,
            "Full Localhost Port Scan Complete",
            (
                f"TCP open ports found: {len(artifact.get('tcp_open_ports', []))}\n"
                f"UDP responsive or unknown ports: {len(artifact.get('udp_responsive_or_unknown_ports', []))}"
            ),
        )

    def run_network_discovery(self) -> None:
        options_dialog = NetworkDiscoveryOptionsDialog(self)
        if options_dialog.exec() != QDialog.Accepted:
            self.statusBar().showMessage("network discovery cancelled", 3000)
            return
        try:
            options = options_dialog.values()
        except (ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Network Discovery", str(exc))
            return
        confirm_dialog = NetworkDiscoveryConfirmDialog(str(options["subnet"]), self)
        if confirm_dialog.exec() != QDialog.Accepted:
            self.statusBar().showMessage("network discovery cancelled", 3000)
            return
        previous = self.db.latest_network_discovery()
        progress_dialog = NetworkDiscoveryProgressDialog(self.collectors, options, previous, self)
        self._active_network_discovery_dialog = progress_dialog
        try:
            progress_dialog.start_scan()
            if progress_dialog.exec() != QDialog.Accepted:
                error = progress_dialog.error
                if error is not None:
                    QMessageBox.warning(self, "Network Discovery", str(error))
                    return
                self.statusBar().showMessage("network discovery cancelled", 3000)
                return
            result, findings, payload = progress_dialog.result_data
        finally:
            self._active_network_discovery_dialog = None
        if self.current_scan_result is None:
            self.current_scan_result = ScanResult(
                scan_id=result.scan_id,
                timestamp=result.timestamp,
                hostname="local-network-discovery",
                current_user="local-user",
                findings=[],
                raw_logs=[],
                collected_artifacts={"network_discovery": payload},
                baseline_diff={},
                errors=[],
            )
            self.current_scan_summary = ScanSummary(
                scan_id=result.scan_id,
                started_at=result.timestamp,
                completed_at=result.timestamp,
                findings_count=len(findings),
                security_score=None,
                notes="Network Discovery evidence only.",
                new_items_count=len(payload.get("comparison", {}).get("new_devices", [])),
                score_label="Unavailable",
            )
            self.current_scan_active = True
        if self.current_payload is None:
            self.current_payload = {
                "findings": [],
                "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
                "localhost_scan": {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
                "localhost_full_port_scan": {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []},
                "packet_captures": [],
                "network_discovery": {"interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "host_count": 0, "review_needed_count": 0, "hosts": [], "devices": [], "comparison": {}, "debug_logs": [], "errors": []},
                "processes": {"all": [], "suspicious": [], "errors": []},
                "users": [],
                "history_indicators": [],
                "permission_snapshots": [],
                "file_issues": [],
                "raw_logs": [],
                "baseline_diff": {},
                "dashboard": {
                    "suspicious_ports": 0,
                    "users_admin_changes": 0,
                    "history_indicators": 0,
                    "suspicious_directories": 0,
                    "new_since_last_scan": 0,
                },
            }
        self.current_payload["network_discovery"] = safe_payload
        self.current_payload.setdefault("findings", []).extend([finding.to_dict() for finding in findings])
        self.current_payload.setdefault("raw_logs", []).extend(result.raw_logs)
        if self.current_scan_result is not None:
            self.current_scan_result.collected_artifacts["network_discovery"] = safe_payload
            self.current_scan_result.raw_logs.extend(result.raw_logs)
            self.current_scan_result.findings.extend(findings)
        if self.current_scan_summary is not None and self.current_scan_result is not None:
            self.current_scan_summary.findings_count = len(self.current_scan_result.findings)
            self.current_scan_summary.completed_at = result.timestamp
            self.current_scan_summary.new_items_count = len(payload.get("comparison", {}).get("new_devices", []))
        safe_payload = json_safe(payload)
        self.db.record_network_discovery(result.scan_id, safe_payload)
        evidence_dir = Path.cwd() / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / f"{result.scan_id}.json").write_text(json.dumps(safe_payload, indent=2), encoding="utf-8")
        self._populate_scan_results(self.current_payload)
        self._refresh_dashboard()
        self.results_tabs.setCurrentWidget(self.network_discovery_page)
        self._refresh_command_preview_page()
        self.statusBar().showMessage("network discovery completed", 5000)
        QMessageBox.information(
            self,
            "Network Discovery Complete",
            (
                f"Mode: {payload.get('scan_profile_label', payload.get('scan_profile', 'standard'))}\n"
                f"Discovered hosts: {len(payload.get('hosts', []))}\n"
                f"Scanned subnet: {payload.get('scan_subnet', payload.get('subnet', ''))}"
            ),
        )

    def closeEvent(self, event) -> None:
        if self.tray_icon is not None and self.tray_icon.isVisible() and not self._force_quit_from_tray:
            event.ignore()
            self.hide()
            self._refresh_tray_status()
            self.tray_icon.showMessage(
                "Mac Audit Agent",
                "Security viewer is still available from the tray icon.",
                QSystemTrayIcon.MessageIcon.Information,
                3000,
            )
            return
        dialog = getattr(self, "_active_network_discovery_dialog", None)
        if dialog is not None:
            dialog.cancel_scan()
            dialog._stop_worker()
        if self.tray_status_timer is not None:
            self.tray_status_timer.stop()
        if self.tray_icon is not None:
            self.tray_icon.hide()
        super().closeEvent(event)

    def run_packet_capture_snapshot(self) -> None:
        if self.config.fresh_baseline_validation_mode or self.config.uat_live_environment_mode or self.config.disable_packet_capture:
            QMessageBox.information(self, "Disabled", "Packet capture is disabled in the current mode.")
            return
        if not tcpdump_available():
            QMessageBox.warning(self, "tcpdump Not Available", "tcpdump was not found at /usr/sbin/tcpdump.")
            return
        options_dialog = PacketCaptureOptionsDialog(self)
        if options_dialog.exec() != QDialog.Accepted:
            self.statusBar().showMessage("packet capture cancelled", 3000)
            return
        try:
            options = options_dialog.values()
        except (ValueError, TypeError) as exc:
            QMessageBox.warning(self, "Invalid Packet Capture Options", str(exc))
            return
        confirm_dialog = PacketCaptureConfirmDialog(self)
        if confirm_dialog.exec() != QDialog.Accepted:
            self.statusBar().showMessage("packet capture cancelled", 3000)
            return
        session = PacketCaptureSession(
            interface=str(options["interface"]),
            duration_seconds=int(options["duration_seconds"]),
            capture_filter=str(options["capture_filter"]),
            evidence_dir=Path(str(options["output_dir"])),
            user_confirmed=True,
        )
        progress = PacketCaptureProgressDialog(session, self)
        progress.start_capture()
        progress.exec()
        result = progress.result
        if result is None:
            self.statusBar().showMessage("packet capture failed", 5000)
            return
        metadata = result.metadata
        if self.current_scan_result is None:
            capture_scan_id = str(metadata.get("capture_id", "packet-capture"))
            self.current_scan_result = ScanResult(
                scan_id=capture_scan_id,
                timestamp=str(metadata.get("end_time", utc_now_iso())),
                hostname="local-packet-capture",
                current_user="local-user",
                findings=[],
                raw_logs=[],
                collected_artifacts={"packet_captures": [], "network_discovery": {"interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "host_count": 0, "review_needed_count": 0, "hosts": [], "devices": [], "comparison": {}, "debug_logs": [], "errors": []}},
                baseline_diff={},
                errors=[],
            )
            self.current_scan_summary = ScanSummary(
                scan_id=capture_scan_id,
                started_at=str(metadata.get("start_time", utc_now_iso())),
                completed_at=str(metadata.get("end_time", utc_now_iso())),
                findings_count=0,
                security_score=100,
                notes="Packet Capture Snapshot evidence only.",
                new_items_count=1,
                score_label="Good",
            )
            self.current_scan_active = True
        if self.current_payload is None:
            self.current_payload = {
                "findings": [],
                "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
                "localhost_scan": {"target": "127.0.0.1", "mode": "safe", "protocol": "tcp", "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
                "localhost_full_port_scan": {"target": "127.0.0.1", "tcp_open_ports": [], "tcp_banners": {}, "udp_responsive_or_unknown_ports": [], "scanned_tcp_count": 0, "scanned_udp_count": 0, "errors": []},
                "packet_captures": [],
                "network_discovery": {"interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "host_count": 0, "review_needed_count": 0, "hosts": [], "devices": [], "comparison": {}, "debug_logs": [], "errors": []},
                "processes": {"all": [], "suspicious": [], "errors": []},
                "users": [],
                "history_indicators": [],
                "permission_snapshots": [],
                "file_issues": [],
                "raw_logs": [],
                "baseline_diff": {},
                "dashboard": {
                    "suspicious_ports": 0,
                    "users_admin_changes": 0,
                    "history_indicators": 0,
                    "suspicious_directories": 0,
                    "new_since_last_scan": 0,
                },
            }
        captures = self.current_payload.setdefault("packet_captures", [])
        captures.append(metadata)
        raw_logs = self.current_payload.setdefault("raw_logs", [])
        raw_logs.extend(result.raw_logs)
        completed_finding_model = None
        if result.finding:
            self.current_payload.setdefault("findings", []).append(result.finding)
        else:
            completed_finding_model = Finding(
                id=f"{metadata['capture_id']}-completed",
                category="Packet Capture Snapshot",
                title="Packet Capture Snapshot completed",
                severity="info",
                description="A user-requested packet capture snapshot completed and was stored locally as evidence.",
                evidence=str(metadata.get("pcap_path", "")),
                command_used=" ".join(str(item) for item in metadata.get("command_used", [])),
                remediation_suggestion="Review the saved pcap in an authorized tool if deeper traffic analysis is needed.",
                warning="Packet captures may contain sensitive metadata or contents and should be handled carefully.",
                evidence_summary=f"interface={metadata.get('interface', '')} duration={metadata.get('duration_seconds', 0)}s status={metadata.get('status', '')}",
                raw_evidence_ref=str(metadata.get("capture_id", "")),
                why_this_matters="This provides bounded local evidence for later review without embedding packet contents in the app report.",
                false_positive_notes="A stored capture is not proof of malicious activity by itself.",
                recommended_next_steps="Review the capture only if you are authorized and need deeper traffic evidence.",
                what_can_go_wrong="Opening or sharing captures broadly can expose sensitive metadata or traffic contents.",
                remediation_steps=["Handle the pcap as sensitive evidence and review it only in an authorized workflow."],
                remediation_risk="sensitive",
                requires_admin=False,
                reversible=True,
                estimated_impact="medium",
                verification_steps=["Confirm the pcap and metadata JSON exist in the evidence directory."],
                remediation_references=["tcpdump manual page: packet captures are local-only evidence and may contain sensitive traffic metadata."],
            )
            self.current_payload.setdefault("findings", []).append(completed_finding_model.to_dict())
        if self.current_scan_result is not None:
            self.current_scan_result.collected_artifacts.setdefault("packet_captures", []).append(metadata)
            self.current_scan_result.raw_logs.extend(result.raw_logs)
            if result.finding:
                self.current_scan_result.findings.append(Finding(**normalize_finding(result.finding)))
            elif completed_finding_model is not None:
                self.current_scan_result.findings.append(completed_finding_model)
        if self.current_scan_summary is not None and self.current_scan_result is not None:
            self.current_scan_summary.findings_count = len(self.current_scan_result.findings)
            self.current_scan_summary.completed_at = str(metadata.get("end_time", utc_now_iso()))
        self._populate_scan_results(self.current_payload)
        self._refresh_dashboard()
        self.results_tabs.setCurrentWidget(self.packet_capture_table)
        self._refresh_command_preview_page()
        if metadata.get("status") == "failed" and "permission denied" in str(metadata.get("stderr_summary", "")).lower():
            QApplication.clipboard().setText(result.manual_command)
            QMessageBox.warning(
                self,
                "Packet Capture Requires Admin",
                "Packet capture requires admin privileges on macOS. Re-run the app with appropriate permissions or run the displayed tcpdump command manually.\n\nThe manual command has been copied to the clipboard.",
            )
        elif metadata.get("status") == "cancelled":
            self.statusBar().showMessage("packet capture cancelled", 5000)
        elif metadata.get("status") == "completed":
            self.statusBar().showMessage("packet capture completed", 5000)
        else:
            self.statusBar().showMessage("packet capture failed", 5000)

    def _populate_findings(self, findings: list[dict | object]) -> None:
        findings = self._sort_findings(deduplicate_findings_for_display(normalize_findings(findings)))
        self.current_visible_findings = findings
        self.findings_table.setRowCount(0)
        for finding in findings:
            evidence_summary = finding.get("evidence_summary", finding.get("evidence", ""))
            occurrence_count = int(finding.get("occurrence_count", 1) or 1)
            if occurrence_count > 1:
                duplicate_category = str(finding.get("duplicate_category", "duplicate_burst") or "duplicate_burst").replace("_", " ")
                evidence_summary = f"{evidence_summary} | Repeated {occurrence_count} times ({duplicate_category})"
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            items = [
                QTableWidgetItem(finding.get("severity", "info")),
                QTableWidgetItem(finding.get("category", "")),
                QTableWidgetItem(finding.get("title", "")),
                QTableWidgetItem(evidence_summary),
            ]
            for column, item in enumerate(items):
                self.findings_table.setItem(row, column, item)
            self._apply_severity_style(items, finding.get("severity", "info"))
        self.findings_table.resizeRowsToContents()
        self._clear_selected_finding_panel()

    def _populate_scan_results(self, payload: dict) -> None:
        self._set_results_available(True)
        self._populate_findings(normalize_findings(payload.get("findings", [])))
        ports = payload["ports"]
        port_rows = [[item.process_name, str(item.pid) if item.pid is not None else "", item.local_address, str(item.port) if item.port is not None else "", item.concern or "Review needed"] for item in ports.get("listening", [])]
        if not port_rows:
            port_message = "No listening ports found."
            if ports.get("errors"):
                port_message = f"No listening ports found. Errors: {'; '.join(ports['errors'])}"
            port_rows = [[port_message, "", "", "", ""]]
        self._populate_table(self.ports_table, port_rows)
        localhost_scan = payload.get("localhost_scan", {})
        open_ports = localhost_scan.get("open_ports", [])
        if isinstance(open_ports, dict):
            open_ports_text = ", ".join(
                f"{proto.upper()}: {', '.join(str(port) for port in ports_list) if ports_list else 'none'}"
                for proto, ports_list in open_ports.items()
            )
        else:
            open_ports_text = ", ".join(str(port) for port in open_ports) if open_ports else "none"
        missing_ports = localhost_scan.get("missing_from_enumeration", [])
        self._populate_table(
            self.localhost_scan_table,
            [
                ["Target", str(localhost_scan.get("target", "127.0.0.1"))],
                ["Scan Mode", str(localhost_scan.get("mode", "safe"))],
                ["Protocol", str(localhost_scan.get("protocol", "tcp")).upper()],
                ["Scanned Port Count", str(localhost_scan.get("scanned_port_count", 0))],
                ["Open Ports Found", open_ports_text],
                ["Ports Missing From Process Enumeration", ", ".join(str(port) for port in missing_ports) if missing_ports else "none"],
                ["Explanation", "This does not scan your network. It only attempts localhost traffic to 127.0.0.1."],
            ],
        )
        localhost_full_scan = payload.get("localhost_full_port_scan", {})
        tcp_banners = localhost_full_scan.get("tcp_banners", {})
        if isinstance(tcp_banners, dict):
            tcp_banner_text = "; ".join(f"{port}: {banner}" for port, banner in sorted(tcp_banners.items())) or "none"
        else:
            tcp_banner_text = "none"
        self._populate_table(
            self.localhost_full_scan_table,
            [
                ["Target", str(localhost_full_scan.get("target", "127.0.0.1"))],
                ["TCP Open Ports", ", ".join(str(port) for port in localhost_full_scan.get("tcp_open_ports", [])) or "none"],
                ["TCP Banners", tcp_banner_text],
                ["UDP Responsive or Unknown Ports", ", ".join(str(port) for port in localhost_full_scan.get("udp_responsive_or_unknown_ports", [])) or "none"],
                ["Scanned TCP Count", str(localhost_full_scan.get("scanned_tcp_count", 0))],
                ["Scanned UDP Count", str(localhost_full_scan.get("scanned_udp_count", 0))],
                ["Errors", "; ".join(str(item) for item in localhost_full_scan.get("errors", [])) or "none"],
                ["Explanation", "This module scans only 127.0.0.1 across TCP and UDP, performs passive TCP banner grabbing, and does not rely on local process enumeration to decide which ports to check."],
            ],
        )
        packet_captures = payload.get("packet_captures", [])
        latest_capture = packet_captures[-1] if packet_captures else {}
        self._populate_table(
            self.packet_capture_table,
            [
                ["Status", str(latest_capture.get("status", "not-run"))],
                ["Capture ID", str(latest_capture.get("capture_id", ""))],
                ["Interface", str(latest_capture.get("interface", ""))],
                ["Duration Seconds", str(latest_capture.get("duration_seconds", ""))],
                ["Filter", str(latest_capture.get("filter", "")) or "none"],
                ["PCAP Path", str(latest_capture.get("pcap_path", ""))],
                ["PCAP SHA256", str(latest_capture.get("pcap_sha256", ""))],
                ["File Size Bytes", str(latest_capture.get("file_size_bytes", ""))],
                ["Command Used", " ".join(str(item) for item in latest_capture.get("command_used", [])) if isinstance(latest_capture.get("command_used"), list) else str(latest_capture.get("command_used", ""))],
                ["Privacy Warning", "Packet captures may contain sensitive traffic metadata or contents. The app stores only local file metadata here and does not embed packet contents."],
            ],
        )
        network_discovery = payload.get("network_discovery", {})
        network_host_rows = []
        for item in network_discovery.get("devices", network_discovery.get("hosts", [])):
            if hasattr(item, "to_dict"):
                item = item.to_dict()
            if not isinstance(item, dict):
                continue
            network_host_rows.append(
                [
                    str(item.get("ip_address", "")),
                    str(item.get("likely_hostname", "")) or "Unknown Host",
                    str(item.get("mac_address", "")),
                    str(item.get("vendor", item.get("vendor_guess", ""))),
                    str(item.get("device_type", "")),
                    str(item.get("confidence", "")),
                    ", ".join(str(value) for value in item.get("discovery_methods", [])),
                    ", ".join(str(value) for value in item.get("review_flags", [])) or str(item.get("notes", "")),
                ]
            )
        if not network_host_rows:
            network_host_rows = [["No devices discovered. Check WiFi interface, subnet detection, and permissions.", "", "", "", "", "", "", ""]]
        comparison = network_discovery.get("comparison", {})
        network_change_rows = []
        for change_type, items in comparison.items():
            if isinstance(items, list):
                for item in items:
                    network_change_rows.append([change_type.replace("_", " ").title(), json.dumps(item, sort_keys=True)])
        if not network_change_rows:
            network_change_rows = [["No baseline changes", "This is the first discovery or nothing changed."]]
        suspicious_network_findings = [
            finding
            for finding in normalize_findings(payload.get("findings", []))
            if finding.get("category") == "Network Discovery"
        ]
        if not suspicious_network_findings:
            suspicious_network_findings = [{"severity": "info", "title": "No suspicious devices identified", "evidence": "Review the baseline and host list if needed."}]
        self._populate_table(
            self.network_discovery_summary_table,
            [
                ["Interface", str(network_discovery.get("interface", ""))],
                ["Mode", str(network_discovery.get("scan_profile_label", network_discovery.get("scan_profile", "standard")))],
                ["Subnet", str(network_discovery.get("subnet", ""))],
                ["Scan Subnet", str(network_discovery.get("scan_subnet", network_discovery.get("subnet", "")))],
                ["Scope", str(network_discovery.get("scope", ""))],
                ["Gateway IP", str(network_discovery.get("gateway_ip", network_discovery.get("gateway", "")))],
                ["Gateway MAC", str(network_discovery.get("gateway_mac", "")) or "unknown"],
                ["Discovered Host Count", str(network_discovery.get("host_count", len(network_discovery.get("hosts", []))))],
                ["Review Needed Devices", str(network_discovery.get("review_needed_count", 0))],
                ["Methods Used", ", ".join(str(item) for item in network_discovery.get("methods_used", [])) or "none"],
                ["Privacy Warning", "This scan identifies devices visible on your local network. A new or unknown device is not proof of compromise, but it may be worth investigating if you do not recognize it."],
            ],
        )
        self._populate_table(self.network_discovery_hosts_table, network_host_rows)
        if self.network_discovery_hosts_table.rowCount() > 0:
            self.network_discovery_hosts_table.selectRow(0)
        self._refresh_network_discovery_device_details()
        debug_rows = [[str(idx + 1), str(entry)] for idx, entry in enumerate(network_discovery.get("debug_logs", []))]
        if not debug_rows:
            debug_rows = [["No debug output", "Discovery completed without debug entries."]]
        self._populate_table(self.network_discovery_debug_table, debug_rows)
        self._populate_table(self.network_discovery_changes_table, network_change_rows)
        self._populate_table(
            self.network_discovery_suspicious_table,
            [[str(item.get("severity", "")), str(item.get("title", "")), str(item.get("evidence", ""))] for item in suspicious_network_findings],
        )
        self._populate_vulnerability_results(payload)
        self._populate_execution_evidence(payload)
        processes = payload.get("processes", {"all": [], "errors": []})
        process_rows = [[item.user, str(item.pid) if item.pid is not None else "", str(item.ppid) if item.ppid is not None else "", item.command_path, item.trust_level, str(item.trust_score), ",".join(item.reasons)] for item in processes.get("all", [])]
        if not process_rows:
            process_message = "No processes parsed."
            if processes.get("errors"):
                process_message = f"No processes parsed. Errors: {'; '.join(processes['errors'])}"
            process_rows = [[process_message, "", "", "", "", "", ""]]
        self._populate_table(self.processes_table, process_rows)
        ports_log_summary = next((item.stdout_summary for item in reversed(payload.get("raw_logs", [])) if item.collector_name == "ports"), "")
        processes_log_summary = next((item.stdout_summary for item in reversed(payload.get("raw_logs", [])) if item.collector_name == "processes"), "")
        self.last_ui_debug = {
            "artifact_keys": list(self.current_scan_result.artifacts.keys()) if self.current_scan_result else [],
            "ports_parsed": len(ports.get("listening", [])),
            "processes_parsed": len(processes.get("all", [])),
            "ports_rows_rendered": len(port_rows),
            "processes_rows_rendered": len(process_rows),
            "ports_errors": ports.get("errors", []),
            "processes_errors": processes.get("errors", []),
            "ports_log_summary": ports_log_summary,
            "processes_log_summary": processes_log_summary,
        }
        if self.current_scan_result is not None:
            self.current_scan_result.raw_logs.extend(
                [
                    RawLogEntry("ui", "ports_table", utc_now_iso(), None, "", f"Ports rows rendered: {len(port_rows)}"),
                    RawLogEntry("ui", "processes_table", utc_now_iso(), None, "", f"Processes rows rendered: {len(process_rows)}"),
                ]
            )
        self.statusBar().showMessage(f"Ports rows rendered: {len(port_rows)} | Processes rows rendered: {len(process_rows)}", 5000)
        self._populate_table(
            self.users_table,
            [[item.username, str(item.uid), str(item.admin), str(item.hidden), item.shell, str(item.authorized_keys_count), item.home] for item in payload["users"]],
        )
        self._populate_table(self.history_table, [[item.shell_type, item.pattern_id, str(item.match_count), item.source_path, item.snippet] for item in payload["history_indicators"]])
        file_rows = [[item.path, item.issue_type, item.modified_at, item.signed_status, getattr(item, "trust_label", ""), str(getattr(item, "trust_score", ""))] for item in payload["file_issues"]]
        file_rows.extend([[item.path, item.issue, item.mode, "permission", "", ""] for item in payload["permission_snapshots"]])
        self._populate_table(self.files_table, file_rows)
        comparison_rows = []
        for change_type, deltas in payload.get("baseline_diff", {}).items():
            if isinstance(deltas, list):
                for delta in deltas:
                    comparison_rows.append([change_type, str(delta.get("item_key", "")), str(delta.get("details", ""))])
        self._populate_table(self.comparison_table, comparison_rows)
        self._populate_table(
            self.logs_table,
            [[item.collector_name, item.command_or_source, item.timestamp, str(item.exit_code) if item.exit_code is not None else "", item.stderr_summary, item.stdout_summary] for item in payload.get("raw_logs", [])],
        )
        self.refresh_investigation_notes_page()

    def _network_discovery_devices(self) -> list[dict]:
        network_discovery = (self.current_payload or {}).get("network_discovery", {})
        devices = network_discovery.get("devices", network_discovery.get("hosts", [])) if isinstance(network_discovery, dict) else []
        normalized: list[dict] = []
        for item in devices:
            if hasattr(item, "to_dict"):
                item = item.to_dict()
            if isinstance(item, dict):
                normalized.append(item)
        return normalized

    def _refresh_network_discovery_device_details(self) -> None:
        devices = self._network_discovery_devices()
        if not hasattr(self, "network_discovery_device_details_table"):
            return
        if not devices:
            self._populate_table(self.network_discovery_device_details_table, [["No device selected", "Run a discovery scan first."]])
            return
        row = self.network_discovery_hosts_table.currentRow()
        if row < 0 or row >= len(devices):
            row = 0
        device = devices[row]
        all_hostnames = [
            str(device.get("likely_hostname", "")),
            str(device.get("hostname", "")),
            str(device.get("mdns_name", "")),
            str(device.get("reverse_dns", "")),
            str(device.get("netbios_name", "")),
            str(device.get("dhcp_hostname", "")),
        ]
        hostname_sources = [item for item in all_hostnames if item]
        baseline_status = str(device.get("baseline_status", "matched baseline") or "matched baseline")
        review_flags = ", ".join(str(value) for value in device.get("review_flags", [])) or "none"
        details_rows = [
            ["Likely Hostname", str(device.get("likely_hostname", "")) or "Unknown Host"],
            ["All Hostnames Found", ", ".join(dict.fromkeys(hostname_sources)) or "none"],
            ["IP Address", str(device.get("ip_address", ""))],
            ["MAC Address", str(device.get("mac_address", "")) or "unknown"],
            ["Vendor", str(device.get("vendor", device.get("vendor_guess", ""))) or "unknown"],
            ["Device Type", str(device.get("device_type", "")) or "unknown"],
            ["Discovery Sources", ", ".join(str(value) for value in device.get("discovery_methods", [])) or "none"],
            ["Baseline Status", baseline_status],
            ["Why Flagged", review_flags if device.get("review_needed") else "No review-needed flags."],
            ["Recommended Next Step", "Review against inventory and confirm whether this device is expected." if device.get("review_needed") else "No follow-up needed."],
        ]
        self._populate_table(self.network_discovery_device_details_table, details_rows)

    def reset_scan_state(self) -> None:
        self.current_scan_result = None
        self.current_scan_summary = None
        self.current_payload = None
        self.current_visible_findings = []
        self.current_scan_active = False
        self.last_ui_debug = {}
        self.execution_evidence_findings = []
        self._set_results_available(False)
        self._populate_findings([])
        self._clear_selected_finding_panel()
        for table_name in [
            "ports_table",
            "localhost_scan_table",
            "localhost_full_scan_table",
            "packet_capture_table",
            "network_discovery_summary_table",
            "network_discovery_hosts_table",
            "network_discovery_device_details_table",
            "network_discovery_debug_table",
            "network_discovery_changes_table",
            "network_discovery_suspicious_table",
            "execution_evidence_table",
            "catalog_status_table",
            "cve_findings_table",
            "best_practice_findings_table",
            "review_needed_findings_table",
            "processes_table",
            "users_table",
            "history_table",
            "files_table",
            "comparison_table",
            "logs_table",
        ]:
            table = getattr(self, table_name, None)
            if table is not None:
                table.setRowCount(0)
        for value in self.dashboard_cards.values():
            value.setText("0")
        for value in self.severity_cards.values():
            value.setText("0")
        self._refresh_dashboard()
        if hasattr(self, "background_monitor_panel"):
            self.background_monitor_panel.refresh()
        if hasattr(self, "investigation_notes_editor"):
            self.investigation_note_title.clear()
            self.investigation_notes_editor.clear()
            self.investigation_investigator_name.clear()
            self.current_investigation_note_id = ""
            self.investigation_progress_label.setText("No scan loaded.")
            self.finding_notes_table.setRowCount(0)
            self.timeline_notes_table.setRowCount(0)
            self.investigation_checklist_table.setRowCount(0)
        self._refresh_command_preview_page()
        self.statusBar().showMessage("scan state cleared", 5000)
        self.refresh_system_recovery(manual=False)

    def _populate_vulnerability_results(self, payload: dict) -> None:
        catalog_status = payload.get("catalog_status", {})
        stats = payload.get("vulnerability_review_stats", {})
        self._populate_table(
            self.catalog_status_table,
            [
                ["Catalog Timestamp", str(catalog_status.get("timestamp", ""))],
                ["Status", str(catalog_status.get("status", "not-run"))],
                ["Data Sources", ", ".join(str(item) for item in catalog_status.get("data_sources_used", [])) or "none"],
                ["Errors", "; ".join(str(item) for item in catalog_status.get("errors", [])) or "none"],
                ["CVEs Evaluated", str(stats.get("cves_evaluated", 0))],
                ["Applicable", str(stats.get("applicable", 0))],
                ["Uncertain / Review Needed", str(stats.get("uncertain_review_needed", 0))],
                ["Top Findings By Risk", ", ".join(str(item) for item in stats.get("top_findings_by_risk", [])) or "none"],
            ],
        )
        cve_findings = normalize_findings(payload.get("cve_findings", []))
        filtered_cve_findings = []
        for finding in cve_findings:
            if self.cve_filter_kev_only.isChecked() and not finding.get("kev", False):
                continue
            if self.cve_filter_epss_high.isChecked() and float(finding.get("epss_percentile") or 0.0) < 0.8:
                continue
            if self.cve_filter_critical_high.isChecked() and finding.get("severity") not in {"critical", "high"}:
                continue
            if self.cve_filter_installed_only.isChecked() and not finding.get("detected_product"):
                continue
            if self.cve_filter_macos_only.isChecked() and finding.get("detected_product") not in {"macOS", "macos"}:
                continue
            filtered_cve_findings.append(finding)
        self._populate_table(
            self.cve_findings_table,
            [
                [
                    str(finding.get("severity", "")),
                    str(finding.get("detected_product", "")),
                    str(finding.get("detected_version", "")),
                    ", ".join(str(item) for item in finding.get("cve_ids", [])),
                    str(finding.get("kev", False)),
                    str(finding.get("epss_percentile", "")),
                    str(finding.get("cvss_score", "")),
                    str(finding.get("confidence", "")),
                    str(finding.get("title", "")),
                ]
                for finding in filtered_cve_findings
            ],
        )
        best_practice_findings = normalize_findings(payload.get("best_practice_findings", []))
        self._populate_table(
            self.best_practice_findings_table,
            [[str(finding.get("severity", "")), str(finding.get("category", "")), str(finding.get("title", "")), str(finding.get("evidence", ""))] for finding in best_practice_findings],
        )
        review_needed_findings = normalize_findings(payload.get("review_needed_findings", []))
        self._populate_table(
            self.review_needed_findings_table,
            [
                [
                    str(finding.get("severity", "")),
                    str(finding.get("detected_product", "")),
                    str(finding.get("detected_version", "")),
                    ", ".join(str(item) for item in finding.get("cve_ids", [])),
                    str(finding.get("confidence", "")),
                    str(finding.get("title", "")),
                ]
                for finding in review_needed_findings
            ],
        )

    def _populate_execution_evidence(self, payload: dict) -> None:
        if not hasattr(self, "execution_evidence_engine") or not hasattr(self, "execution_evidence_table"):
            return
        scan_result = self.current_scan_result
        if scan_result is None:
            self.execution_evidence_findings = []
            self._populate_table(self.execution_evidence_table, [["No scan loaded", "", "", "", ""]])
            return
        findings = [item.to_dict() for item in self.execution_evidence_engine.analyze_scan(scan_result)]
        self.execution_evidence_findings = findings
        rows: list[list[str]] = []
        for finding in findings:
            timeline = " | ".join(
                f"{entry.get('timestamp', '')} {entry.get('event', '')}: {entry.get('details', '')}".strip()
                for entry in finding.get("timeline", [])
            )
            rows.append(
                [
                    str(finding.get("confidence", "low")),
                    str(finding.get("title", "")),
                    timeline,
                    str(finding.get("explanation", "")),
                    ", ".join(str(step) for step in finding.get("next_steps", [])),
                ]
            )
        if not rows:
            rows = [["No execution evidence detected", "", "", "No evidence-only execution indicators were assembled from the current scan.", "Review the scan and run the relevant collectors again if needed."]]
        self._populate_table(self.execution_evidence_table, rows)

    def _populate_table(self, table: QTableWidget, rows: list[list[str]]) -> None:
        table.setRowCount(0)
        for row_data in rows:
            row = table.rowCount()
            table.insertRow(row)
            for column, value in enumerate(row_data):
                table.setItem(row, column, QTableWidgetItem(value))
        table.resizeRowsToContents()

    def show_last_collector_debug(self) -> None:
        if self.current_scan_result is None:
            QMessageBox.information(self, "Diagnostics", "No scan loaded.")
            return
        relevant_logs = [
            f"[{entry.collector_name}] {entry.command_or_source} exit={entry.exit_code} stderr={entry.stderr_summary} stdout={entry.stdout_summary}"
            for entry in self.current_scan_result.raw_logs
            if entry.collector_name in {"ports", "processes"}
        ]
        debug_text = "\n".join(
            [
                f"Artifact keys present: {', '.join(self.last_ui_debug.get('artifact_keys', []))}",
                f"Ports parsed: {self.last_ui_debug.get('ports_parsed', 0)}",
                f"Processes parsed: {self.last_ui_debug.get('processes_parsed', 0)}",
                f"Ports rows rendered: {self.last_ui_debug.get('ports_rows_rendered', 0)}",
                f"Processes rows rendered: {self.last_ui_debug.get('processes_rows_rendered', 0)}",
                f"Ports errors: {self.last_ui_debug.get('ports_errors', [])}",
                f"Processes errors: {self.last_ui_debug.get('processes_errors', [])}",
                f"Ports raw summary: {self.last_ui_debug.get('ports_log_summary', '')}",
                f"Processes raw summary: {self.last_ui_debug.get('processes_log_summary', '')}",
                "",
                "Collector logs:",
                *relevant_logs,
            ]
        )
        QMessageBox.information(self, "Last Collector Debug", debug_text[:12000])

    def export_json(self) -> None:
        if not self._ensure_scan_state():
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON Report", str(default_json_report_path()), "JSON Files (*.json)")
        if not path:
            return
        include_background_monitor_logs = self._confirm_include_background_monitor_logs()
        include_investigation_notes = self._confirm_include_investigation_notes()
        background_monitor_events = [item.to_dict() for item in self.db.recent_background_monitor_events(limit=1000)] if include_background_monitor_logs else []
        investigation_notes = [item.to_dict() for item in self.db.list_investigation_notes(linked_scan_id=self._current_scan_id(), limit=1000)] if include_investigation_notes else []
        investigation_audit_trail = [item.to_dict() for item in self.db.list_investigation_audit_trail(limit=1000)] if include_investigation_notes else []
        try:
            investigation_priorities = self.investigation_priority_engine.build_priorities(scan_result=self.current_scan_result).to_dict() if self.current_scan_result else None
            saved_path = export_scan_result_json(
                self.current_scan_result,
                Path(path),
                include_background_monitor_logs=include_background_monitor_logs,
                background_monitor_events=background_monitor_events,
                include_investigation_notes=include_investigation_notes,
                investigation_notes=investigation_notes,
                investigation_audit_trail=investigation_audit_trail,
                investigation_priorities=investigation_priorities,
            )
        except OSError as exc:
            self.statusBar().showMessage("export failed", 5000)
            QMessageBox.critical(self, "Export Failed", f"Failed to export JSON report:\n{exc}")
            return
        self.statusBar().showMessage("report exported", 5000)
        QMessageBox.information(self, "JSON Report Exported", f"Saved JSON report to:\n{saved_path}")

    def export_html(self) -> None:
        if not self._ensure_scan_state():
            return
        default_report_path = str(default_html_report_path())
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML Report", default_report_path, "HTML Files (*.html)")
        if not path:
            return
        include_background_monitor_logs = self._confirm_include_background_monitor_logs()
        include_investigation_notes = self._confirm_include_investigation_notes()
        background_monitor_events = [item.to_dict() for item in self.db.recent_background_monitor_events(limit=1000)] if include_background_monitor_logs else []
        investigation_notes = [item.to_dict() for item in self.db.list_investigation_notes(linked_scan_id=self._current_scan_id(), limit=1000)] if include_investigation_notes else []
        investigation_audit_trail = [item.to_dict() for item in self.db.list_investigation_audit_trail(limit=1000)] if include_investigation_notes else []
        try:
            investigation_priorities = self.investigation_priority_engine.build_priorities(scan_result=self.current_scan_result).to_dict() if self.current_scan_result else None
            saved_path = export_scan_result_html(
                self.current_scan_result,
                Path(path),
                include_background_monitor_logs=include_background_monitor_logs,
                background_monitor_events=background_monitor_events,
                include_investigation_notes=include_investigation_notes,
                investigation_notes=investigation_notes,
                investigation_audit_trail=investigation_audit_trail,
                investigation_priorities=investigation_priorities,
            )
        except OSError as exc:
            self.statusBar().showMessage("export failed", 5000)
            QMessageBox.critical(self, "Export Failed", f"Failed to export HTML report:\n{exc}")
            return
        self.statusBar().showMessage("report exported", 5000)
        QMessageBox.information(self, "HTML Report Exported", f"Saved HTML report to:\n{saved_path}")

    def open_reports_folder(self) -> None:
        reports_dir = get_reports_dir()
        try:
            reports_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(["open", str(reports_dir)], check=False)
        except Exception as exc:
            QMessageBox.warning(self, "Open Reports Folder Failed", f"Failed to open reports folder:\n{reports_dir}\n\n{exc}")
            return
        QMessageBox.information(self, "Open Reports Folder", f"Reports folder opened:\n{reports_dir}")

    def _confirm_include_background_monitor_logs(self) -> bool:
        message = (
            "Include Background Monitor Logs in this report?\n\n"
            "These are local privacy and session indicators only. They do not contain camera images, audio, screen contents, keystrokes, or packet contents."
        )
        return QMessageBox.question(self, "Include Background Monitor Logs", message) == QMessageBox.StandardButton.Yes

    def _confirm_include_investigation_notes(self) -> bool:
        message = (
            "Include Investigation Notes in this report?\n\n"
            "Notes may contain sensitive case information and remain local to the exported file."
        )
        return QMessageBox.question(self, "Include Investigation Notes", message) == QMessageBox.StandardButton.Yes

    def _ensure_scan_state(self) -> bool:
        if self.current_scan_result is None:
            QMessageBox.warning(self, "No Scan Data", "Run a scan before exporting a report.")
            return False
        return True

    def _apply_severity_style(self, items: list[QTableWidgetItem], severity: str) -> None:
        if severity not in SEVERITY_COLOR_MAP:
            return
        bg_color, fg_color = severity_qcolors(severity)
        bg = QBrush(bg_color)
        fg = QBrush(fg_color)
        for item in items:
            item.setBackground(bg)
            item.setForeground(fg)
