from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.ui.severity_styles import apply_severity_to_table_item


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
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        subtitle = QLabel("App, storage, monitor, notifier, forecast, and export health in one place.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.summary_label = QLabel("No health report loaded yet.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("color: #D6E4FF; font-weight: 700;")
        layout.addWidget(self.summary_label)

        self.security_banner = QLabel("")
        self.security_banner.setWordWrap(True)
        self.security_banner.setStyleSheet("background: #7A271A; color: #FFFFFF; font-weight: 800; padding: 10px; border: 2px solid #FDA29B;")
        layout.addWidget(self.security_banner)

        self.why_label = QLabel("Why this is happening: No health report loaded yet.")
        self.action_label = QLabel("What you can do: Refresh Operational Health.")
        self.fix_options_label = QLabel("Fix options: none")
        for label in [self.why_label, self.action_label, self.fix_options_label]:
            label.setWordWrap(True)
            label.setStyleSheet("color: #D6E4FF;")
            layout.addWidget(label)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.repair_button = QPushButton("Repair Operational Health")
        self.repair_button.setToolTip("Attempt safe repairs for broken MSAA operational components such as notifier, monitor, settings drift, database schema, and log paths.")
        self.enable_settings_button = QPushButton("Enable in Settings")
        self.enable_settings_button.setToolTip("Open Settings for components that are disabled by user preference.")
        self.audit_button = QPushButton("Audit System Monitor Deployment")
        self.verify_button = QPushButton("Verify Event Flow")
        self.verify_integrity_button = QPushButton("Verify Now")
        self.verify_system_integrity_button = QPushButton("Verify System Monitor Integrity")
        self.verify_notifier_integrity_button = QPushButton("Verify User Notifier Integrity")
        self.view_mismatch_details_button = QPushButton("View Mismatches")
        self.resolve_mismatch_button = QPushButton("Resolve Mismatch")
        self.preserve_evidence_snapshot_button = QPushButton("Preserve Evidence Snapshot")
        self.create_manifest_button = QPushButton("Create Trusted Manifest")
        self.export_integrity_report_button = QPushButton("Export Integrity Report")
        self.recalculate_manifest_button = QPushButton("Recalculate Manifest After Trusted Update")
        self.verify_integrity_button.setToolTip("Verify MSAA files against an existing trusted integrity manifest.")
        self.verify_system_integrity_button.setToolTip("Verify the deployed system monitor runtime and LaunchDaemon against its trusted manifest.")
        self.verify_notifier_integrity_button.setToolTip("Verify the user notifier runtime and LaunchAgent against its trusted manifest.")
        self.view_mismatch_details_button.setToolTip("Show exact manifest/current build differences and file mismatch details.")
        self.resolve_mismatch_button.setToolTip("Open the safe resolver for stale or incompatible integrity manifest states.")
        self.preserve_evidence_snapshot_button.setToolTip("Create an evidence snapshot before investigating modified integrity files.")
        self.create_manifest_button.setToolTip("Record current MSAA files as trusted after a trusted install or build.")
        self.export_integrity_report_button.setToolTip("Export the current application integrity verification result as JSON.")
        self.recalculate_manifest_button.setToolTip("Create a new trusted manifest after an intentional trusted MSAA update.")
        self.repair_button.setStyleSheet("font-weight: 700; background: #B42318; color: white;")
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
            self.repair_button,
            self.enable_settings_button,
            self.audit_button,
            self.verify_button,
        ]:
            button.setMinimumHeight(36)
            button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
            button.setToolTip(button.text())
            toolbar.addWidget(button)
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
        layout.addLayout(toolbar)

        details_title = QLabel("Operational Health Details")
        details_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #F0F6FC;")
        layout.addWidget(details_title)

        self.component_table = _make_table(["Component", "Status", "Reason", "Last Check", "Fix"])
        layout.addWidget(self.component_table, 1)

        issue_title = QLabel("Root Causes")
        issue_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #F0F6FC;")
        layout.addWidget(issue_title)

        self.issue_table = _make_table(["Rank", "Component", "Severity", "Category", "Issue", "Evidence", "Suggested Fix"])
        layout.addWidget(self.issue_table, 1)

        self.table = _make_table(["Component", "Status", "Summary", "Evidence", "Next Step"])
        layout.addWidget(self.table, 1)

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
        self.set_developer_mode(False)

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
            self.action_label.setText(f"What you can do: {suggested or 'Review evidence before taking action.'}")
            self.fix_options_label.setText(f"Fix options: {primary.get('component', '')} | evidence: {evidence or 'none'}")
        elif issues:
            self.why_label.setText(f"Why this is happening: {issues[0].get('title', 'Operational issue')}")
            self.action_label.setText("What you can do: review the ranked root causes below.")
            self.fix_options_label.setText("Fix options: see each component row.")
        elif overall.lower() == "healthy":
            self.why_label.setText("Why this is happening: all monitored operational components are healthy.")
            self.action_label.setText("What you can do: no action required.")
            self.fix_options_label.setText("Fix options: none")
        else:
            self.why_label.setText("Why this is happening: Operational Health could not determine a complete state.")
            self.action_label.setText("What you can do: refresh health and review diagnostics.")
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
                if column == 2:
                    apply_severity_to_table_item(item, value, text=value.upper() if value else "UNKNOWN")
                self.issue_table.setItem(row, column, item)
        self.issue_table.resizeRowsToContents()
