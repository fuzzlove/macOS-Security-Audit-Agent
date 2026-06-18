from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def _table(headers: list[str]) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SingleSelection)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.setWordWrap(True)
    widget.verticalHeader().setVisible(False)
    widget.horizontalHeader().setStretchLastSection(True)
    return widget


def _set_rows(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setRowCount(0)
    for values in rows:
        row = table.rowCount()
        table.insertRow(row)
        for column, value in enumerate(values):
            table.setItem(row, column, QTableWidgetItem(value))
    table.resizeRowsToContents()


class ReliabilityPanel(QFrame):
    refresh_requested = Signal()
    incident_mode_enable_requested = Signal()
    incident_mode_disable_requested = Signal()
    incident_create_snapshot_requested = Signal()
    incident_open_timeline_requested = Signal()
    incident_export_case_package_requested = Signal()
    incident_add_note_requested = Signal()
    incident_review_high_priority_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("reliabilityPanel")
        self._build_ui()
        self.set_payload({})

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("Reliability & Release Readiness")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        header.addWidget(title, 1)
        header.addWidget(self.refresh_button)
        layout.addLayout(header)

        self.summary_label = QLabel("No reliability report loaded yet.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("color: #D6E4FF; font-weight: 700;")
        layout.addWidget(self.summary_label)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.alert_table = _table(["Field", "Value"])
        self.trace_table = _table(
            [
                "Trace",
                "Event",
                "Original",
                "Canonical",
                "Detector",
                "Stored",
                "Notifier",
                "Policy",
                "Cooldown",
                "Suppression",
                "Required",
                "Queued",
                "Overlay",
                "Visible",
                "Displayed",
            ]
        )
        self.coverage_table = _table(["Component", "Status", "Last Run", "Last Event", "Last Error", "Heartbeat Age", "Permission", "Failure", "Fix"])
        self.release_table = _table(["Check", "Status", "Evidence", "Fix"])
        self.trust_table = _table(["Time", "Event", "Score", "Delta", "Cause", "Action"])
        self.drift_table = _table(["Setting", "Severity", "Confidence", "Previous", "Current", "Seen", "Verification"])
        self.incident_text = QTextEdit()
        self.incident_text.setReadOnly(True)
        incident_page = QWidget()
        incident_layout = QVBoxLayout(incident_page)
        incident_buttons = QHBoxLayout()
        self.enable_incident_button = QPushButton("Enable Incident Mode")
        self.disable_incident_button = QPushButton("Disable Incident Mode")
        self.enable_incident_button.clicked.connect(self.incident_mode_enable_requested.emit)
        self.disable_incident_button.clicked.connect(self.incident_mode_disable_requested.emit)
        incident_buttons.addWidget(self.enable_incident_button)
        incident_buttons.addWidget(self.disable_incident_button)
        incident_layout.addLayout(incident_buttons)
        incident_action_buttons = QHBoxLayout()
        self.incident_snapshot_button = QPushButton("Create Evidence Snapshot")
        self.incident_timeline_button = QPushButton("Open Timeline")
        self.incident_export_button = QPushButton("Export Case Package")
        self.incident_note_button = QPushButton("Add Investigation Note")
        self.incident_priority_button = QPushButton("Review High Priority Events")
        self.incident_snapshot_button.clicked.connect(self.incident_create_snapshot_requested.emit)
        self.incident_timeline_button.clicked.connect(self.incident_open_timeline_requested.emit)
        self.incident_export_button.clicked.connect(self.incident_export_case_package_requested.emit)
        self.incident_note_button.clicked.connect(self.incident_add_note_requested.emit)
        self.incident_priority_button.clicked.connect(self.incident_review_high_priority_requested.emit)
        for button in [
            self.incident_snapshot_button,
            self.incident_timeline_button,
            self.incident_export_button,
            self.incident_note_button,
            self.incident_priority_button,
        ]:
            incident_action_buttons.addWidget(button)
        incident_layout.addLayout(incident_action_buttons)
        incident_layout.addWidget(self.incident_text, 1)

        self.tabs.addTab(self.alert_table, "Alert Pipeline Health")
        self.tabs.addTab(self.trace_table, "Recent Alert Traces")
        self.tabs.addTab(self.coverage_table, "Monitoring Coverage")
        self.tabs.addTab(self.release_table, "Release Readiness")
        self.tabs.addTab(self.trust_table, "Trust Timeline")
        self.tabs.addTab(self.drift_table, "Configuration Drift")
        self.tabs.addTab(incident_page, "Incident Mode")

    def set_payload(self, payload: dict[str, Any]) -> None:
        alert = payload.get("alert_pipeline", {}) if isinstance(payload.get("alert_pipeline", {}), dict) else {}
        coverage = payload.get("monitoring_coverage", {}) if isinstance(payload.get("monitoring_coverage", {}), dict) else {}
        release = payload.get("release_readiness", {}) if isinstance(payload.get("release_readiness", {}), dict) else {}
        trust = payload.get("trust_decay", {}) if isinstance(payload.get("trust_decay", {}), dict) else {}
        drift = payload.get("configuration_drift", {}) if isinstance(payload.get("configuration_drift", {}), dict) else {}
        incident = payload.get("incident_mode", {}) if isinstance(payload.get("incident_mode", {}), dict) else {}

        self.summary_label.setText(
            "Monitoring Coverage: {coverage}% | Release Readiness: {release}% ({status}) | Trust: {trust_score} ({trend})".format(
                coverage=coverage.get("MonitoringCoverageScore", coverage.get("score", 0)),
                release=release.get("ReleaseReadinessScore", 0),
                status=release.get("status", "unknown"),
                trust_score=trust.get("current_score", "--"),
                trend=trust.get("trend", "unknown"),
            )
        )

        _set_rows(
            self.alert_table,
            [
                ["last event detected", str(alert.get("last_event_detected", ""))],
                ["last event stored", str(alert.get("last_event_stored", ""))],
                ["last event consumed by notifier", str(alert.get("last_event_consumed_by_notifier", ""))],
                ["last alert shown", str(alert.get("last_alert_shown", ""))],
                ["last failure stage", str(alert.get("last_failure_stage", ""))],
                ["suppressed count", str(alert.get("suppressed_count", 0))],
                ["no_policy_match count", str(alert.get("no_policy_match_count", 0))],
                ["DB path mismatch status", str(alert.get("db_path_mismatch_status", "unknown"))],
            ],
        )
        _set_rows(
            self.trace_table,
            [
                [
                    str(item.get("trace_id", "")),
                    str(item.get("event_id", "")),
                    str(item.get("original_event_type", "")),
                    str(item.get("canonical_event_type", item.get("normalized_event_type", item.get("event_type", "")))),
                    str(item.get("detector_source", "")),
                    "yes" if item.get("stored_success") else "no",
                    "yes" if item.get("notifier_seen") else "no",
                    f"{item.get('policy_result', item.get('notification_policy_result', ''))}: {item.get('policy_reason', item.get('notification_policy_reason', ''))}",
                    str(item.get("cooldown_result", "")),
                    str(item.get("suppression_reason", item.get("alert_suppression_reason", ""))),
                    "yes" if item.get("alert_required") else "no",
                    "yes" if item.get("alert_queue_enqueued") else "no",
                    f"{item.get('overlay_dispatch_result', '')}: {item.get('overlay_error', '')}",
                    str(item.get("visible_alert_id", "")),
                    str(item.get("displayed_at", "")),
                ]
                for item in alert.get("traces", [])
            ],
        )
        _set_rows(
            self.coverage_table,
            [
                [
                    str(item.get("component", "")),
                    str(item.get("status", "")),
                    str(item.get("last_successful_run", "")),
                    str(item.get("last_event", "")),
                    str(item.get("last_error", "")),
                    str(item.get("heartbeat_age_seconds", "")),
                    str(item.get("permission_status", "")),
                    str(item.get("failure_reason", "")),
                    str(item.get("recommended_fix", "")),
                ]
                for item in coverage.get("components", [])
            ],
        )
        _set_rows(
            self.release_table,
            [
                [str(item.get("check", "")), str(item.get("status", "")), str(item.get("evidence", "")), str(item.get("recommended_fix", ""))]
                for item in release.get("checks", [])
            ],
        )
        trust_items = trust.get("score_history") or trust.get("timeline", [])
        _set_rows(
            self.trust_table,
            [
                [
                    str(item.get("created_at", item.get("timestamp", ""))),
                    str(item.get("event_type", ", ".join(str(event.get("event_type", "")) for event in item.get("related_events", []) if isinstance(event, dict)))),
                    f"{item.get('previous_score', '')} -> {item.get('current_score', '')}",
                    str(item.get("delta", "")),
                    ", ".join(str(cause) for cause in item.get("causes", [])) or str(item.get("cause", "")),
                    str(item.get("recommended_action", "")),
                ]
                for item in trust_items
            ],
        )
        _set_rows(
            self.drift_table,
            [
                [
                    str(item.get("setting", "")),
                    str(item.get("severity", "")),
                    str(item.get("confidence", "")),
                    str(item.get("previous_value", "")),
                    str(item.get("current_value", "")),
                    str(item.get("last_seen", "")),
                    str(item.get("recommended_verification", "")),
                ]
                for item in drift.get("changes", [])
            ],
        )
        actions = incident.get("recommended_actions", [])
        self.incident_text.setPlainText(
            "\n".join(
                [
                    str(incident.get("banner", "Incident Mode inactive.")),
                    f"Cleanup blocked: {'yes' if incident.get('cleanup_blocked') else 'no'}",
                    f"Persistent high/critical alerts: {'yes' if incident.get('high_critical_alerts_persistent') else 'no'}",
                    f"Evidence snapshots: {incident.get('evidence_snapshot_count', 0)}",
                    f"Case packages: {incident.get('case_package_count', 0)}",
                    f"Investigation note actions: {incident.get('investigation_note_count', 0)}",
                    f"Last evidence snapshot: {incident.get('last_evidence_snapshot', {}).get('path', '') if isinstance(incident.get('last_evidence_snapshot', {}), dict) else ''}",
                    f"Last case package: {incident.get('last_case_package', {}).get('path', '') if isinstance(incident.get('last_case_package', {}), dict) else ''}",
                    "",
                    "Actions:",
                    *[f"- {item}" for item in actions],
                ]
            )
        )
