from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.ui.button_factory import create_button, create_export_button, create_repair_button, create_toolbar_button
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow
from mac_audit_agent.ui.severity_styles import apply_severity_to_table_item


_TERMINAL_COMMAND_PREFIXES = (
    "/",
    "./",
    "bash ",
    "codesign ",
    "defaults ",
    "env ",
    "launchctl ",
    "open ",
    "pfctl ",
    "pkgutil ",
    "python",
    "security ",
    "sh ",
    "spctl ",
    "sudo ",
    "zsh ",
)


def _copyable_action_text(text: str) -> str:
    """Return paste-ready plain text without Markdown fences or shell prompts."""

    cleaned = str(text or "").strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3:
            cleaned = "\n".join(lines[1:-1]).strip()
    lines = cleaned.splitlines()
    if lines and all(not line.strip() or line.lstrip().startswith("$ ") for line in lines):
        cleaned = "\n".join(
            line.lstrip()[2:] if line.lstrip().startswith("$ ") else ""
            for line in lines
        ).strip()
    return cleaned


def _is_terminal_command(text: str) -> bool:
    first_line = str(text or "").strip().splitlines()[0].strip() if str(text or "").strip() else ""
    return first_line.startswith(_TERMINAL_COMMAND_PREFIXES)


def _make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    return table


class OperationalHealthPanel(QFrame):
    refresh_requested = Signal()
    audit_deployment_requested = Signal()
    verify_event_flow_requested = Signal()
    repair_requested = Signal()
    enable_settings_requested = Signal()
    verify_application_integrity_requested = Signal()
    verify_system_monitor_integrity_requested = Signal()
    verify_user_notifier_integrity_requested = Signal()
    create_trusted_manifest_requested = Signal()
    resolve_integrity_mismatch_requested = Signal()
    view_integrity_mismatch_details_requested = Signal()
    export_integrity_report_requested = Signal()
    preserve_integrity_evidence_snapshot_requested = Signal()
    install_active_protection_requested = Signal()
    repair_active_protection_requested = Signal()
    verify_active_protection_requested = Signal()
    export_protection_diagnostics_requested = Signal()
    repair_component_requested = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("operationalHealthPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._build_ui()
        self.set_report({})

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Operational Health")
        title.setProperty("textRole", "cardTitle")
        subtitle = QLabel("App, storage, monitor, notifier, forecast, and export health in one place.")
        subtitle.setWordWrap(True)
        subtitle.setProperty("textRole", "muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.summary_label = QLabel("No health report loaded yet.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("font-weight: 700;")
        layout.addWidget(self.summary_label)

        self.security_banner = QLabel("")
        self.security_banner.setWordWrap(True)
        self.security_banner.setStyleSheet("background: #7A271A; color: #FFFFFF; font-weight: 800; padding: 10px; border: 2px solid #FDA29B;")
        layout.addWidget(self.security_banner)

        self.why_label = QLabel("Why this is happening: No health report loaded yet.")
        self.action_heading_label = QLabel("What can you do now?")
        self.action_heading_label.setProperty("textRole", "sectionTitle")
        self.action_label = QLabel("Refresh Operational Health.")
        self.fix_options_label = QLabel("Fix options: none")
        for label in [self.why_label, self.fix_options_label]:
            label.setWordWrap(True)
            label.setProperty("textRole", "muted")
            layout.addWidget(label)
        layout.addWidget(self.action_heading_label)
        action_row = QHBoxLayout()
        self.action_label.setWordWrap(True)
        self.action_label.setTextFormat(Qt.PlainText)
        self.action_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        self.action_label.setAccessibleName("Suggested Operational Health action")
        self._default_action_font = self.action_label.font()
        self.action_label.setProperty("textRole", "muted")
        action_row.addWidget(self.action_label, 1)
        self.copy_action_button = create_toolbar_button(
            "Copy Guidance",
            tooltip="Copy the displayed Operational Health guidance exactly without executing it.",
        )
        self.copy_action_button.setAccessibleName("Copy suggested Operational Health fix")
        self.copy_action_button.clicked.connect(self._copy_suggested_fix)
        action_row.addWidget(self.copy_action_button)
        layout.addLayout(action_row)

        toolbar = ResponsiveActionRow()
        self.refresh_button = create_toolbar_button("Refresh")
        self.repair_button = create_repair_button("Repair Operational Health", tooltip="Attempt safe repairs for broken MSAA operational components such as notifier, monitor, settings drift, database schema, and log paths.")
        self.enable_settings_button = create_button("Enable in Settings", tooltip="Open Settings for components that are disabled by user preference.")
        self.audit_button = create_toolbar_button("Audit System Monitor Deployment")
        self.audit_button.setToolTip("Verify launchd state, heartbeat freshness, canonical database alignment, permissions, and notifier delivery without changing the deployment.")
        self.audit_button.setAccessibleName("Audit system monitor deployment")
        self.audit_button.setAccessibleDescription(self.audit_button.toolTip())
        self.verify_button = create_toolbar_button("Verify Event Flow")
        self.verify_integrity_button = create_toolbar_button("Verify Now", tooltip="Verify MSAA files against an existing trusted integrity manifest.")
        self.verify_system_integrity_button = create_toolbar_button("Verify System Monitor Integrity", tooltip="Verify the deployed system monitor runtime and LaunchDaemon against its trusted manifest.")
        self.verify_notifier_integrity_button = create_toolbar_button("Verify User Notifier Integrity", tooltip="Verify the user notifier runtime and LaunchAgent against its trusted manifest.")
        self.view_mismatch_details_button = create_toolbar_button("View Mismatches", tooltip="Show exact manifest/current build differences and file mismatch details.")
        self.resolve_mismatch_button = create_toolbar_button("Resolve Mismatch", tooltip="Open the safe resolver for stale or incompatible integrity manifest states.")
        self.preserve_evidence_snapshot_button = create_toolbar_button("Preserve Evidence Snapshot", tooltip="Create an evidence snapshot before investigating modified integrity files.")
        self.create_manifest_button = create_toolbar_button("Create Trusted Manifest", tooltip="Record current MSAA files as trusted after a trusted install or build.")
        self.export_integrity_report_button = create_export_button("Export Integrity Report", tooltip="Export the current application integrity verification result as JSON.")
        self.recalculate_manifest_button = create_repair_button("Recalculate Manifest After Trusted Update", tooltip="Create a new trusted manifest after an intentional trusted MSAA update.")
        self.install_protection_button = create_button("Install Active Protection", tooltip="Run the shared headless installation backend. Administrator approval is required for the system LaunchDaemon; MSAA never invokes sudo silently.")
        self.repair_protection_button = create_repair_button("Repair Active Protection", tooltip="Back up and repair daemon, notifier, runtime alignment, and settings without erasing events.")
        self.verify_protection_button = create_toolbar_button("Verify Active Protection", tooltip="Inspect live launchctl state, heartbeats, database alignment, runtime manifest, and alert delivery without changing the host.")
        self.export_protection_button = create_export_button("Export Protection Diagnostics", tooltip="Export the current sanitized Active Protection doctor result.")
        for button in [
            self.refresh_button,
            self.verify_integrity_button,
            self.verify_system_integrity_button,
            self.verify_notifier_integrity_button,
            self.view_mismatch_details_button,
            self.resolve_mismatch_button,
            self.preserve_evidence_snapshot_button,
            self.create_manifest_button,
            self.export_integrity_report_button,
            self.recalculate_manifest_button,
            self.install_protection_button,
            self.repair_protection_button,
            self.verify_protection_button,
            self.export_protection_button,
            self.repair_button,
            self.enable_settings_button,
            self.audit_button,
            self.verify_button,
        ]:
            toolbar.add_button(button)
        self.verify_integrity_button.setToolTip("Verify MSAA files against an existing trusted integrity manifest.")
        self.verify_system_integrity_button.setToolTip("Verify the deployed system monitor runtime and LaunchDaemon against its trusted manifest.")
        self.verify_notifier_integrity_button.setToolTip("Verify the user notifier runtime and LaunchAgent against its trusted manifest.")
        self.view_mismatch_details_button.setToolTip("Shows exact manifest/current build differences, cache status, and changed file details.")
        self.resolve_mismatch_button.setToolTip("Shows exact manifest/current build differences and safe next steps. It never trusts current files without confirmation.")
        self.preserve_evidence_snapshot_button.setToolTip("Preserves current evidence before reinstalling or reviewing modified files.")
        self.create_manifest_button.setToolTip("Records current files as trusted. Only use after installing or building MSAA from a trusted source.")
        self.export_integrity_report_button.setToolTip("Exports status, selected manifest, exact mismatch reason, cache state, and file mismatches.")
        self.recalculate_manifest_button.setToolTip("Recalculates trusted hashes only after the same explicit trusted-install confirmation.")
        self.repair_button.setToolTip("Attempt safe repairs for broken MSAA operational components such as notifier, monitor, settings drift, database schema, and log paths.")
        layout.addWidget(toolbar)

        details_title = QLabel("Operational Health Details")
        details_title.setProperty("textRole", "sectionTitle")
        layout.addWidget(details_title)

        self.component_table = _make_table(["Component", "Status", "Reason", "Last Check", "Fix"])
        layout.addWidget(self.component_table, 1)

        issue_title = QLabel("Root Causes")
        issue_title.setProperty("textRole", "sectionTitle")
        layout.addWidget(issue_title)

        self.issue_table = _make_table(["Rank", "Component", "Severity", "Category", "Issue", "Evidence", "Suggested Fix"])
        layout.addWidget(self.issue_table, 1)

        self.table = _make_table(["Component", "Status", "Summary", "Evidence", "Next Step"])
        layout.addWidget(self.table, 1)
        for health_table in (self.component_table,self.issue_table,self.table):
            health_table.setContextMenuPolicy(Qt.CustomContextMenu); health_table.customContextMenuRequested.connect(lambda position,source=health_table:self._show_repair_menu(source,position))

        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.repair_button.clicked.connect(self.repair_requested.emit)
        self.enable_settings_button.clicked.connect(self.enable_settings_requested.emit)
        self.audit_button.clicked.connect(self.audit_deployment_requested.emit)
        self.verify_button.clicked.connect(self.verify_event_flow_requested.emit)
        self.verify_integrity_button.clicked.connect(self.verify_application_integrity_requested.emit)
        self.verify_system_integrity_button.clicked.connect(self.verify_system_monitor_integrity_requested.emit)
        self.verify_notifier_integrity_button.clicked.connect(self.verify_user_notifier_integrity_requested.emit)
        self.view_mismatch_details_button.clicked.connect(self.view_integrity_mismatch_details_requested.emit)
        self.resolve_mismatch_button.clicked.connect(self.resolve_integrity_mismatch_requested.emit)
        self.preserve_evidence_snapshot_button.clicked.connect(self.preserve_integrity_evidence_snapshot_requested.emit)
        self.create_manifest_button.clicked.connect(self.create_trusted_manifest_requested.emit)
        self.export_integrity_report_button.clicked.connect(self.export_integrity_report_requested.emit)
        self.recalculate_manifest_button.clicked.connect(self.create_trusted_manifest_requested.emit)
        self.install_protection_button.clicked.connect(self.install_active_protection_requested.emit)
        self.repair_protection_button.clicked.connect(self.repair_active_protection_requested.emit)
        self.verify_protection_button.clicked.connect(self.verify_active_protection_requested.emit)
        self.export_protection_button.clicked.connect(self.export_protection_diagnostics_requested.emit)
        self.set_developer_mode(False)

    def _show_repair_menu(self,table: QTableWidget,position) -> None:
        item=table.itemAt(position)
        if item is None: return
        payload=item.data(Qt.UserRole) or {}
        if not isinstance(payload,dict): return
        status=str(payload.get("status") or payload.get("severity") or "").lower()
        repairable=status in {"degraded","broken","critical","repair recommended","unavailable"}
        menu=QMenu(table); repair=menu.addAction(f"Repair {payload.get('component','component')}"); repair.setEnabled(repairable); repair.triggered.connect(lambda:self.repair_component_requested.emit(dict(payload))); menu.addSeparator(); copy=menu.addAction("Copy Suggested Fix"); suggested=payload.get("next_step") or payload.get("fix_label") or payload.get("suggested_fix") or "Review component evidence."; copy.triggered.connect(lambda:QApplication.clipboard().setText("; ".join(str(value) for value in suggested) if isinstance(suggested,list) else str(suggested))); menu.exec(table.viewport().mapToGlobal(position))

    def _set_suggested_fix(self, text: str, *, copyable: bool = True) -> None:
        self._suggested_fix_text = _copyable_action_text(text)
        self._suggested_fix_is_command = _is_terminal_command(self._suggested_fix_text)
        self.action_label.setText(self._suggested_fix_text)
        self.action_label.setFont(
            QFontDatabase.systemFont(QFontDatabase.FixedFont)
            if self._suggested_fix_is_command
            else self._default_action_font
        )
        self.copy_action_button.setText("Copy Command" if self._suggested_fix_is_command else "Copy Guidance")
        self.copy_action_button.setToolTip(
            "Copy the exact command syntax for pasting into Terminal. The command is not executed."
            if self._suggested_fix_is_command
            else "Copy the displayed Operational Health guidance exactly without executing it."
        )
        self.copy_action_button.setVisible(bool(copyable and self._suggested_fix_text))

    def _copy_suggested_fix(self) -> None:
        text = getattr(self, "_suggested_fix_text", "").strip()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.copy_action_button.setText("Copied")

    def set_developer_mode(self, enabled: bool) -> None:
        self.verify_button.setVisible(enabled)
        self.verify_button.setToolTip(
            "Developer Mode only: verifies synthetic event flow through the monitor pipeline."
            if enabled
            else "Hidden unless Settings > Developer Mode is enabled."
        )

    def set_report(self, payload: dict[str, Any]) -> None:
        checks = list(payload.get("checks", []))
        overall = str(payload.get("overall_status", "unknown"))
        display_status = str(payload.get("display_status") or overall)
        issues = list(payload.get("issues", []))
        primary = payload.get("primary_cause") if isinstance(payload.get("primary_cause"), dict) else None
        security_mode = bool(payload.get("security_degraded_mode"))
        if not security_mode:
            source_integrity_for_mode = payload.get("details", {}).get("source_integrity", {}) if isinstance(payload.get("details", {}), dict) else {}
            if isinstance(source_integrity_for_mode, dict):
                security_mode = str(source_integrity_for_mode.get("overall_status", source_integrity_for_mode.get("status", ""))).lower() == "modified"
        if overall.lower() in {"degraded", "broken", "critical"} and not primary and checks:
            first_bad = next((check for check in checks if str(check.get("status", "")).lower() not in {"healthy", "disabled_by_settings", "unsupported"}), None)
            if first_bad:
                display_status = f"{overall.title()} ({first_bad.get('component', 'Unknown')}: {first_bad.get('summary', 'No explanation')})"
        self.summary_label.setText(f"Overall status: {display_status} | Health score: {payload.get('health_score', 0)}/100 | Checks: {len(checks)}")
        if security_mode:
            self.security_banner.setText(
                "SECURITY DEGRADED MODE: Possible program modification or tampering detected. "
                "Review exact mismatches, export evidence, and reinstall from a trusted source if this was not an approved update."
            )
            self.security_banner.setVisible(True)
        else:
            self.security_banner.setVisible(False)
        if primary:
            evidence = "; ".join(str(item) for item in primary.get("evidence", [])[:3]) if isinstance(primary.get("evidence", []), list) else str(primary.get("evidence", ""))
            suggested = "; ".join(str(item) for item in primary.get("suggested_fix", [])[:3]) if isinstance(primary.get("suggested_fix", []), list) else str(primary.get("suggested_fix", ""))
            self.why_label.setText(f"Why this is happening: {primary.get('title', 'Operational issue')} - {primary.get('description', '')}")
            self._set_suggested_fix(suggested or "Review evidence before taking action.")
            self.fix_options_label.setText(f"Fix options: {primary.get('component', '')} | evidence: {evidence or 'none'}")
        elif issues:
            self.why_label.setText(f"Why this is happening: {issues[0].get('title', 'Operational issue')}")
            self._set_suggested_fix("Review the ranked root causes below.")
            self.fix_options_label.setText("Fix options: see each component row.")
        elif overall.lower() == "healthy":
            self.why_label.setText("Why this is happening: all monitored operational components are healthy.")
            self._set_suggested_fix("No action required.", copyable=False)
            self.fix_options_label.setText("Fix options: none")
        else:
            self.why_label.setText("Why this is happening: Operational Health could not determine a complete state.")
            self._set_suggested_fix("Refresh health and review diagnostics.")
            self.fix_options_label.setText("Fix options: review unavailable components.")
        statuses = {str(check.get("status", "")).lower() for check in checks}
        source_integrity = payload.get("details", {}).get("source_integrity", {}) if isinstance(payload.get("details", {}), dict) else {}
        integrity_status = str(source_integrity.get("overall_status", source_integrity.get("status", ""))).lower() if isinstance(source_integrity, dict) else ""
        repairable = bool(statuses & {"broken", "degraded", "repair recommended", "unavailable"})
        disabled_only = bool(statuses) and statuses <= {"healthy", "disabled_by_settings"}
        unsupported_only = bool(statuses) and statuses <= {"healthy", "unsupported"}
        dangerous_issue = security_mode or any(bool(issue.get("risk_of_tampering")) for issue in issues if isinstance(issue, dict))
        safe_issue = any(bool(issue.get("auto_fixable")) for issue in issues if isinstance(issue, dict)) or repairable
        self.repair_button.setVisible(safe_issue and not dangerous_issue and not disabled_only and not unsupported_only)
        self.enable_settings_button.setVisible(disabled_only)
        show_integrity_actions = integrity_status in {"stale", "incompatible_manifest", "unknown", "draft", "modified", "failed", "partial"}
        self.view_mismatch_details_button.setVisible(show_integrity_actions)
        self.resolve_mismatch_button.setVisible(integrity_status in {"stale", "incompatible_manifest", "unknown", "draft"})
        self.preserve_evidence_snapshot_button.setVisible(integrity_status == "modified" or security_mode)
        self.create_manifest_button.setVisible(integrity_status in {"unknown", "draft", "stale"})
        self.export_integrity_report_button.setVisible(bool(integrity_status))
        self._populate_component_table(payload)
        self._populate_issue_table(payload)
        self.table.setRowCount(0)
        for check in checks:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                str(check.get("component", "")),
                str(check.get("status", "")),
                str(check.get("summary", "")),
                str(check.get("evidence", "")),
                str(check.get("next_step", "")),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole,dict(check))
                if column == 1:
                    apply_severity_to_table_item(item, value, text=value.upper() if value else "UNKNOWN")
                self.table.setItem(row, column, item)
        self.table.resizeRowsToContents()

    def _populate_component_table(self, payload: dict[str, Any]) -> None:
        components = list(payload.get("components", []))
        if not components:
            components = [
                {
                    "component": str(check.get("component", "")),
                    "status": str(check.get("status", "")),
                    "reason": str(check.get("summary", "")),
                    "last_check_timestamp": str(payload.get("generated_at", "")),
                    "fix_label": str(check.get("next_step", "")),
                    "auto_fixable": False,
                }
                for check in payload.get("checks", [])
            ]
        self.component_table.setRowCount(0)
        for component in components:
            row = self.component_table.rowCount()
            self.component_table.insertRow(row)
            values = [
                str(component.get("component", "")),
                str(component.get("status_label") or component.get("status", "")),
                str(component.get("reason", "")),
                str(component.get("last_check_timestamp", "")),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole,dict(component))
                if column == 1:
                    apply_severity_to_table_item(item, str(component.get("status", "")), text=value.upper() if value else "UNKNOWN")
                self.component_table.setItem(row, column, item)
            fix_label = str(component.get("fix_label") or "Review")
            button = QPushButton(fix_label)
            button.setMinimumHeight(28)
            button.setToolTip(fix_label)
            if bool(component.get("risk_of_tampering")):
                button.clicked.connect(self.view_integrity_mismatch_details_requested.emit)
                button.setStyleSheet("font-weight: 700; background: #B42318; color: white;")
            elif bool(component.get("auto_fixable")):
                button.clicked.connect(self.repair_requested.emit)
            else:
                button.setEnabled(False)
            self.component_table.setCellWidget(row, 4, button)
        self.component_table.resizeRowsToContents()

    def _populate_issue_table(self, payload: dict[str, Any]) -> None:
        issues = list(payload.get("issues", []))
        ranking = {str(item.get("issue_id", "")): str(item.get("rank", "")) for item in payload.get("root_cause_ranking", []) if isinstance(item, dict)}
        self.issue_table.setRowCount(0)
        if not issues:
            return
        for index, issue in enumerate(issues, start=1):
            row = self.issue_table.rowCount()
            self.issue_table.insertRow(row)
            evidence = "; ".join(str(item) for item in issue.get("evidence", [])[:3]) if isinstance(issue.get("evidence", []), list) else str(issue.get("evidence", ""))
            suggested = "; ".join(str(item) for item in issue.get("suggested_fix", [])[:2]) if isinstance(issue.get("suggested_fix", []), list) else str(issue.get("suggested_fix", ""))
            values = [
                ranking.get(str(issue.get("issue_id", "")), str(index)),
                str(issue.get("component", "")),
                str(issue.get("severity", "")),
                str(issue.get("category", "")),
                str(issue.get("title", "")),
                evidence,
                suggested,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole,dict(issue))
                if column == 2:
                    apply_severity_to_table_item(item, value, text=value.upper() if value else "UNKNOWN")
                self.issue_table.setItem(row, column, item)
        self.issue_table.resizeRowsToContents()
