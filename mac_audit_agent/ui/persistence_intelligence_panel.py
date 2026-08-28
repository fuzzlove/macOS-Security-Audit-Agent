from __future__ import annotations

import json
import html
import getpass
import plistlib
from collections import Counter
from pathlib import Path
from typing import Any
from uuid import uuid4

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QInputDialog,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.persistence_intelligence.baseline import (
    INSECURE_BASELINE_DISCLAIMER, RISK_ACCEPTANCE_PHRASE,
    PersistenceBaselineManager, insecure_baseline_reasons,
)
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.persistence_intelligence.chain_view import build_chain_view
from mac_audit_agent.persistence_intelligence.diagnostics import build_diagnostics
from mac_audit_agent.persistence_intelligence.report_adapter import (
    export_persistence_incident_bundle, export_persistence_report_docx,
    export_persistence_report_html, export_persistence_report_json,
    export_persistence_report_csv, export_persistence_report_excel,
    export_persistence_report_markdown, export_persistence_report_pdf,
    export_persistence_report_text,
)
from mac_audit_agent.persistence_intelligence.scanner import PersistenceIntelligenceEngine
from mac_audit_agent.persistence_intelligence.models import PersistenceItem
from mac_audit_agent.persistence_intelligence.remediation import plan_removal, quarantine_removal
from mac_audit_agent.persistence_intelligence.timeline import build_timeline
from mac_audit_agent.persistence_intelligence.trust_store import PersistenceTrustStore
from mac_audit_agent.reporting import get_reports_dir
from mac_audit_agent.rootkit_detection.diagnostics import run_rootkit_review
from mac_audit_agent.rootkit_detection.evidence import export_evidence_package
from mac_audit_agent.rootkit_detection.report import export_rootkit_report_html, export_rootkit_report_json, export_rootkit_report_professional
from mac_audit_agent.ui.button_factory import create_compact_button, create_export_button, create_primary_button
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow
from mac_audit_agent.ui.risk_colors import apply_risk_item_style, display_risk_label, risk_badge_html


def _display(value: Any, *, unavailable: str = "Unknown") -> str:
    if value is None or value == "":
        return unavailable
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if str(item).strip()) or unavailable
    return str(value)


def _short(value: Any, *, limit: int = 92, unavailable: str = "Unknown") -> str:
    text = _display(value, unavailable=unavailable)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


class PersistenceIntelligencePanel(QWidget):
    scan_completed = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.engine = PersistenceIntelligenceEngine()
        self.baselines = PersistenceBaselineManager()
        self.trust_store = PersistenceTrustStore()
        self.report = None
        self.rootkit_result = None
        self._rootkit_scan_error = ""
        self._finding_detail_payloads: list[dict[str, Any]] = []
        self._all_inventory_rows: list[dict[str, Any]] = []
        self._all_finding_rows: list[dict[str, Any]] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        header = QHBoxLayout()
        header.addStretch(1)
        self.scan_button = QPushButton("Run Persistence + Rootkit Scan")
        self.scan_button.setToolTip("Run read-only persistence, rootkit-suspect, and kernel/system-extension checks; then refresh inventory, findings, coverage, timeline, and diagnostics.")
        self.scan_button.clicked.connect(self.run_scan)
        header.addWidget(self.scan_button)
        self.export_button = QPushButton("Export Report")
        self.export_button.setToolTip("Export the current Persistence Intelligence report in a static, documentation-friendly format.")
        self.export_button.clicked.connect(lambda: self.export_report("html"))
        header.addWidget(self.export_button)
        layout.addLayout(header)
        self.summary = QLabel("No persistence scan has run yet.")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet("color: #D0D7E2; font-weight: 600;")
        layout.addWidget(self.summary)
        filter_grid = QGridLayout()
        filter_grid.setHorizontalSpacing(8)
        filter_grid.setVerticalSpacing(6)
        filter_grid.addWidget(QLabel("Search persistence results"), 0, 0)
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search label, path, target, owner, mechanism, or evidence")
        self.search_box.setAccessibleName("Search persistence results")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setMinimumWidth(280)
        self.severity_filter = self._filter_combo("All severities")
        self.risk_filter = self._filter_combo("All risks")
        self.mechanism_filter = self._filter_combo("All mechanisms")
        self.baseline_filter = self._filter_combo("All baseline states")
        self.signature_filter = self._filter_combo("All signatures")
        self.trust_filter = self._filter_combo("All trust labels")
        self.scanner_filter = self._filter_combo("All scanner sources")
        filter_grid.addWidget(self.search_box, 0, 1, 1, 3)
        for index, widget in enumerate([
            self.severity_filter,
            self.risk_filter,
            self.mechanism_filter,
            self.baseline_filter,
            self.signature_filter,
            self.trust_filter,
            self.scanner_filter,
        ]):
            filter_grid.addWidget(widget, 1 + index // 4, index % 4)
        filter_grid.setColumnStretch(3, 1)
        layout.addLayout(filter_grid)
        self.search_box.textChanged.connect(self._apply_filters)
        for combo in [
            self.severity_filter,
            self.risk_filter,
            self.mechanism_filter,
            self.baseline_filter,
            self.signature_filter,
            self.trust_filter,
            self.scanner_filter,
        ]:
            combo.currentTextChanged.connect(self._apply_filters)
        self.tabs = QTabWidget()
        self.inventory_table = self._table(["Mechanism", "Label / Name", "Path", "Target", "Loaded", "Disabled", "RunAtLoad", "KeepAlive", "Owner", "Permissions", "Signature", "Trust", "Risk", "Baseline", "Developer", "Team ID", "MITRE", "First Seen", "Last Seen", "Analyst Status", "Removal"])
        self.findings_table = self._table(["Severity", "Risk", "Confidence", "Mechanism", "Name / Label", "Target Path", "Owner", "Signature", "Baseline Status", "Why Flagged", "Recommended Action", "First Seen", "Status", "CVSS", "MITRE", "NIST / CIS", "Removal"])
        for table in (self.inventory_table, self.findings_table):
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda position, source=table: self._show_remediation_menu(source, position))
            table.cellClicked.connect(lambda row, column, source=table: self._remediation_cell_clicked(source, row, column))
        self.findings_table.currentCellChanged.connect(self._show_selected_finding_detail)
        self.chain_text = QTextEdit()
        self.chain_text.setReadOnly(True)
        self.timeline_table = self._table(["Timestamp", "Event", "Severity", "Mechanism", "Label"])
        self.coverage_table = self._table(["Scanner", "Rating", "Items", "Findings", "Why It Passed / Failed", "How to Reach or Retain Pass"])
        self.diagnostics_text = QTextEdit()
        self.diagnostics_text.setReadOnly(True)
        baseline_page = QWidget()
        baseline_layout = QVBoxLayout(baseline_page)
        row = QHBoxLayout()
        row.addWidget(QLabel("Baseline name"))
        self.baseline_name = QLineEdit("trusted")
        row.addWidget(self.baseline_name)
        self.create_baseline_button = QPushButton("Create Trusted Baseline")
        self.create_baseline_button.setToolTip("Save the current persistence inventory as a trusted baseline.")
        self.create_baseline_button.clicked.connect(self.create_baseline)
        row.addWidget(self.create_baseline_button)
        self.compare_baseline_button = QPushButton("Compare Current State")
        self.compare_baseline_button.setToolTip("Compare the current persistence scan against the named baseline.")
        self.compare_baseline_button.clicked.connect(self.compare_baseline)
        row.addWidget(self.compare_baseline_button)
        baseline_layout.addLayout(row)
        self.baseline_text = QTextEdit()
        self.baseline_text.setReadOnly(True)
        baseline_layout.addWidget(self.baseline_text)
        reports_page = QWidget()
        reports_layout = QVBoxLayout(reports_page)
        report_intro = QLabel(
            "Professional Liquidsky Network Security reports use one consistent persistence inventory and contain no macros, "
            "scripts, formulas, external relationships, or embedded executables."
        )
        report_intro.setWordWrap(True)
        reports_layout.addWidget(report_intro)
        self.export_txt_button = QPushButton("Export Plain Text (Safest)")
        self.export_csv_button = QPushButton("Export CSV")
        self.export_pdf_button = QPushButton("Export Static PDF")
        self.export_docx_button = QPushButton("Export Word Document")
        self.export_xlsx_button = QPushButton("Export Excel Workbook")
        self.export_html_button = QPushButton("Export Static HTML")
        self.export_json_button = QPushButton("Export JSON")
        self.export_md_button = QPushButton("Export Markdown")
        self.export_bundle_button = QPushButton("Export Incident Response Bundle")
        report_actions = ResponsiveActionRow(spacing=10)
        report_actions.add_buttons([
            self.export_html_button, self.export_pdf_button, self.export_docx_button, self.export_xlsx_button,
            self.export_csv_button, self.export_txt_button, self.export_md_button, self.export_json_button, self.export_bundle_button,
        ])
        reports_layout.addWidget(report_actions)
        reports_layout.addStretch(1)
        self.export_txt_button.clicked.connect(lambda: self.export_report("txt"))
        self.export_csv_button.clicked.connect(lambda: self.export_report("csv"))
        self.export_pdf_button.clicked.connect(lambda: self.export_report("pdf"))
        self.export_docx_button.clicked.connect(lambda: self.export_report("docx"))
        self.export_xlsx_button.clicked.connect(lambda: self.export_report("xlsx"))
        self.export_html_button.clicked.connect(lambda: self.export_report("html"))
        self.export_json_button.clicked.connect(lambda: self.export_report("json"))
        self.export_md_button.clicked.connect(lambda: self.export_report("md"))
        self.export_bundle_button.clicked.connect(lambda: self.export_report("bundle"))
        dashboard_page = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_page)
        dashboard_layout.setSpacing(10)
        self.dashboard_state_label = QLabel("No persistence scan has been run yet. Run Persistence Scan to populate this section.")
        self.dashboard_state_label.setWordWrap(True)
        self.dashboard_state_label.setStyleSheet("font-weight: 700; color: #D0D7E2;")
        dashboard_layout.addWidget(self.dashboard_state_label)
        self.summary_card_grid = QGridLayout()
        self.summary_cards: dict[str, tuple[QLabel, QLabel]] = {}
        for index, title_text in enumerate(["Total Persistence Items", "High-Risk Findings", "New Since Baseline", "Suspicious Targets", "Rootkit Suspects", "Risky Extensions", "Scanner Coverage"]):
            card = QFrame()
            card.setObjectName("persistenceSummaryCard")
            card.setFrameShape(QFrame.StyledPanel)
            card_layout = QVBoxLayout(card)
            title_label = QLabel(title_text)
            title_label.setStyleSheet("font-weight: 700; color: #E5EEF7;")
            value_label = QLabel("Not scanned")
            value_label.setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF;")
            detail_label = QLabel("Run Persistence Scan to populate this card.")
            detail_label.setWordWrap(True)
            detail_label.setStyleSheet("color: #B7C3D0;")
            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(detail_label)
            self.summary_cards[title_text] = (value_label, detail_label)
            self.summary_card_grid.addWidget(card, index // 3, index % 3)
        dashboard_layout.addLayout(self.summary_card_grid)
        self.top_risks_table = self._table(["Rank", "Severity", "Item", "Mechanism", "Risk Reason", "Action"])
        self.top_risks_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.top_risks_table.customContextMenuRequested.connect(lambda position: self._show_remediation_menu(self.top_risks_table, position))
        self.top_risks_table.cellClicked.connect(self._top_risk_clicked)
        self.top_risks_table.cellDoubleClicked.connect(lambda row, _column: self._open_top_risk(row))
        dashboard_layout.addWidget(QLabel("Top Persistence Risks"))
        dashboard_layout.addWidget(self.top_risks_table)
        self.mechanism_table = self._table(["Mechanism", "Items", "Findings", "Highest Risk"])
        dashboard_layout.addWidget(QLabel("Mechanism Breakdown"))
        dashboard_layout.addWidget(self.mechanism_table)
        self.dashboard_coverage_table = self._table(["Scanner", "Rating", "Items", "Findings", "Why It Passed / Failed", "How to Reach or Retain Pass"])
        self.dashboard_coverage_table.cellDoubleClicked.connect(lambda row, _column: self._open_coverage_detail(row))
        dashboard_layout.addWidget(QLabel("Scanner Coverage"))
        dashboard_layout.addWidget(self.dashboard_coverage_table)
        self.tabs.addTab(dashboard_page, "Dashboard")
        self.tabs.addTab(self.inventory_table, "Inventory")
        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        findings_layout.addWidget(self.findings_table)
        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setMinimumHeight(180)
        self.finding_detail.setPlainText("Select a persistence finding to view details.")
        findings_layout.addWidget(self.finding_detail)
        self.finding_actions = QHBoxLayout()
        for label in ["Add Note", "Mark Reviewed", "Mark Expected", "Open Timeline", "Export Finding"]:
            button = QPushButton(label)
            button.setToolTip(f"{label} for the selected persistence finding.")
            button.setEnabled(False)
            self.finding_actions.addWidget(button)
        findings_layout.addLayout(self.finding_actions)
        self.tabs.addTab(findings_page, "Findings")
        self.tabs.addTab(self.chain_text, "Chain View")
        self.tabs.addTab(self.timeline_table, "Timeline")
        self.tabs.addTab(baseline_page, "Baselines")
        self.tabs.addTab(self.coverage_table, "Coverage")
        self.tabs.addTab(self._build_rootkit_page(), "Rootkits & Kernel Extensions")
        self.tabs.addTab(self.diagnostics_text, "Diagnostics")
        self.tabs.addTab(reports_page, "Reports")
        layout.addWidget(self.tabs)
        self._set_initial_empty_state()

    def _build_rootkit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(8)
        intro = QLabel(
            "Read-only review of system integrity posture, privileged extensions, local listener visibility, and correlated rootkit-like advanced persistence indicators."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #D0D7E2; font-weight: 600;")
        layout.addWidget(intro)
        actions = ResponsiveActionRow()
        self.rootkit_run_button = create_primary_button(
            "Run Rootkit Review",
            tooltip="Run read-only Rootkit & Advanced Persistence suspect review.",
            accessible_name="Run Rootkit Suspect Review",
            on_click=self.run_rootkit_review,
        )
        self.rootkit_integrity_button = create_compact_button(
            "Refresh Integrity",
            tooltip="Refresh SIP, authenticated root, SSV, Gatekeeper, FileVault, and boot argument posture.",
            accessible_name="Refresh System Integrity",
            on_click=lambda: self.run_rootkit_review(system_integrity=True, extensions=False, ports=False, correlate=False, dylib_hijacks=False),
        )
        self.rootkit_extensions_button = create_compact_button(
            "Review Extensions",
            tooltip="Inventory kernel, system, network, DriverKit, and Endpoint Security extensions where observable.",
            accessible_name="Review Extensions",
            on_click=lambda: self.run_rootkit_review(system_integrity=False, extensions=True, ports=False, correlate=False, dylib_hijacks=False),
        )
        self.rootkit_ports_button = create_compact_button(
            "Check Local Ports",
            tooltip="Compare local listener visibility with lsof and netstat without external scanning.",
            accessible_name="Check Local Ports",
            on_click=lambda: self.run_rootkit_review(system_integrity=False, extensions=False, ports=True, correlate=False, dylib_hijacks=False),
        )
        self.rootkit_export_button = create_export_button(
            "Export Evidence",
            tooltip="Export the current Rootkit & Advanced Persistence evidence package for manual review.",
            accessible_name="Export Rootkit Evidence",
            on_click=self.export_rootkit_evidence,
        )
        actions.add_buttons(
            [
                self.rootkit_run_button,
                self.rootkit_integrity_button,
                self.rootkit_extensions_button,
                self.rootkit_ports_button,
                self.rootkit_export_button,
            ]
        )
        layout.addWidget(actions)
        self.rootkit_summary = QLabel("No rootkit suspect review has run yet.")
        self.rootkit_summary.setWordWrap(True)
        layout.addWidget(self.rootkit_summary)
        self.rootkit_posture_table = self._table(["Control", "What This Protection Does", "Status", "Evidence / Notes", "Why It Passes / Fails", "How to Meet Expected SIP Posture"])
        self.rootkit_extension_table = self._table(["Type", "Bundle ID", "Team ID", "Loaded", "Path", "Signature", "Risk Flags", "Removal"])
        self.rootkit_extension_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rootkit_extension_table.customContextMenuRequested.connect(lambda position: self._show_remediation_menu(self.rootkit_extension_table, position))
        self.rootkit_extension_table.cellClicked.connect(lambda row, column: self._remediation_cell_clicked(self.rootkit_extension_table, row, column))
        self.rootkit_ports_table = self._table(["Protocol", "Port", "Bind", "PID", "Owner", "lsof", "netstat", "Probe", "Status", "Severity"])
        self.rootkit_findings_table = self._table(["Severity", "Confidence", "Category", "Title", "Evidence", "Recommended Fix", "Removal"])
        self.rootkit_findings_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rootkit_findings_table.customContextMenuRequested.connect(lambda position: self._show_remediation_menu(self.rootkit_findings_table, position))
        self.rootkit_findings_table.cellClicked.connect(lambda row, column: self._remediation_cell_clicked(self.rootkit_findings_table, row, column))
        layout.addWidget(QLabel("System Integrity Posture"))
        layout.addWidget(self.rootkit_posture_table)
        layout.addWidget(QLabel("Extension Inventory"))
        layout.addWidget(self.rootkit_extension_table)
        layout.addWidget(QLabel("Suspicious Ports / Visibility"))
        layout.addWidget(self.rootkit_ports_table)
        layout.addWidget(QLabel("Correlated Suspect Findings"))
        layout.addWidget(self.rootkit_findings_table)
        return page

    def _filter_combo(self, empty_label: str) -> QComboBox:
        combo = QComboBox()
        combo.addItem(empty_label)
        combo.setMinimumWidth(130)
        return combo

    def _table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        return table

    def _set_initial_empty_state(self) -> None:
        self._set_filter_controls_enabled(False)
        self.dashboard_state_label.setText("No persistence scan has been run yet. Run Persistence Scan to populate this section.")
        self._fill_table(self.top_risks_table, [["", "No elevated persistence risks detected.", "", "", "", "Run Persistence Scan"]])
        self._fill_table(self.mechanism_table, [["No data", "Not scanned", "Not scanned", "Unknown"]])
        self._fill_table(self.dashboard_coverage_table, [["No scanner data", "Not scanned", "0", "0", "Not scanned", "Run Persistence Scan"]])
        self._fill_table(self.inventory_table, [["No persistence data available yet.", "", "", "", "", "", "", "", "", "", "", "Unknown", "Unknown", "Unknown"]])
        self._fill_table(self.findings_table, [["No persistence findings detected.", "", "", "", "", "", "", "", "", "", "", "", ""]])

    def run_scan(self) -> None:
        try:
            self.dashboard_state_label.setText("Running Persistence Intelligence scan...")
            self.summary.setText("Running persistence, rootkit-suspect, and privileged-extension checks...")
            self.report = self.engine.scan()
            self.rootkit_summary.setText("Running read-only rootkit and kernel/system extension review...")
            self._rootkit_scan_error = ""
            try:
                self.rootkit_result = run_rootkit_review(
                    mode="quick",
                    local_only=True,
                    system_integrity=True,
                    extensions=True,
                    ports=True,
                    correlate=True,
                    dylib_hijacks=True,
                )
                self._render_rootkit_result()
                self._record_rootkit_security_events()
            except Exception as rootkit_exc:
                self.rootkit_result = None
                self._rootkit_scan_error = f"{type(rootkit_exc).__name__}: {rootkit_exc}"
                self.rootkit_summary.setText("Rootkit and privileged-extension coverage is unavailable. Review Diagnostics and rerun.")
            self._render_report()
            self._set_filter_controls_enabled(True)
            self.scan_completed.emit(self.report)
        except Exception as exc:
            self.dashboard_state_label.setText("Persistence Intelligence failed. View Diagnostics.")
            self.summary.setText("Persistence Intelligence failed. View Diagnostics.")
            QMessageBox.warning(self, "Persistence Scan Failed", str(exc))

    def _set_filter_controls_enabled(self, enabled: bool) -> None:
        controls = [
            self.search_box, self.severity_filter, self.risk_filter, self.mechanism_filter,
            self.baseline_filter, self.signature_filter, self.trust_filter, self.scanner_filter,
        ]
        for control in controls:
            control.setEnabled(enabled)
            control.setToolTip(
                "Filter the current persistence scan results."
                if enabled else "Run Persistence Scan before filtering results."
            )

    def _render_report(self) -> None:
        if self.report is None:
            return
        rootkit = self._rootkit_metrics()
        critical_high = sum(1 for finding in self.report.findings if finding.severity in {"CRITICAL", "HIGH"})
        unsigned = sum(1 for item in self.report.items if item.signed_status == "unsigned")
        suspicious = sum(1 for item in self.report.items if any("command invokes" in evidence for evidence in item.evidence))
        writable = sum(1 for item in self.report.items if item.world_writable)
        techniques = sorted({tech for item in self.report.items for tech in item.mitre_techniques})
        self.summary.setText(
            f"Items: {len(self.report.items)} | Findings: {len(self.report.findings)} | Critical/High: {critical_high} | "
            f"Unsigned: {unsigned} | Suspicious commands: {suspicious} | World-writable references: {writable} | "
            f"Rootkit suspects: {rootkit['findings']} | Risky privileged extensions: {rootkit['risky_extensions']} | "
            f"MITRE techniques: {', '.join(techniques) or 'none'} | Posture score: {self.report.posture_score} | Last scan: {self.report.completed_at}"
        )
        self._render_dashboard()
        self._all_inventory_rows = [self._inventory_row(item) for item in self.report.items]
        self._all_finding_rows = [self._finding_row(finding) for finding in self.report.findings]
        self._populate_filters()
        self._apply_filters()
        self._fill_table(self.timeline_table, [[event["timestamp"], event["event"], event["severity"], event["mechanism"], event["label"]] for event in build_timeline(self.report.items)])
        self._fill_table(self.coverage_table, self._coverage_rows())
        self.chain_text.setHtml(self._chain_view_html())
        diagnostics = build_diagnostics(self.report)
        diagnostics["rootkit_and_extension_review"] = {
            "status": "unavailable" if self._rootkit_scan_error else "completed" if self.rootkit_result is not None else "not_run",
            "error": self._rootkit_scan_error,
            "metrics": self._rootkit_metrics(),
            "limitations": list(getattr(self.rootkit_result, "limitations", []) or []),
        }
        self.diagnostics_text.setPlainText(json.dumps(diagnostics, indent=2, sort_keys=True))
        self.finding_detail.setPlainText("Select a persistence finding to view details.")

    def _render_dashboard(self) -> None:
        if self.report is None:
            self._set_initial_empty_state()
            return
        critical = sum(1 for finding in self.report.findings if finding.severity == "CRITICAL")
        high = sum(1 for finding in self.report.findings if finding.severity == "HIGH")
        added = sum(1 for item in self.report.items if item.baseline_status == "new")
        changed = sum(1 for item in self.report.items if item.baseline_status in {"changed", "modified", "hash_changed"})
        unsigned = sum(1 for item in self.report.items if item.signed_status in {"unsigned", "invalid"})
        temp_targets = sum(1 for item in self.report.items if any(marker in (item.executable_path or item.program or item.path) for marker in ["/tmp", "/var/tmp", "/private/tmp", "/Users/Shared"]))
        missing_targets = sum(1 for item in self.report.items if not item.target_exists and (item.program or item.executable_path))
        scanner_errors = [c for c in self.report.coverage if c.get("error_count", 0) or str(c.get("coverage_status", "")).lower() in {"failed", "degraded", "partial"}]
        rootkit = self._rootkit_metrics()
        if self._rootkit_scan_error:
            self.dashboard_state_label.setText("Persistence scan completed, but rootkit and privileged-extension coverage is unavailable. Review Diagnostics and rerun.")
        elif rootkit["findings"] or rootkit["risky_extensions"]:
            self.dashboard_state_label.setText(
                f"Persistence scan completed with {rootkit['findings']} rootkit-like suspect finding(s) and "
                f"{rootkit['risky_extensions']} risky privileged extension(s). These are investigation leads, not confirmed malware."
            )
        else:
            self.dashboard_state_label.setText("No persistence or rootkit-like suspect findings detected." if not self.report.findings else "Persistence Intelligence scan completed. Review top risks first.")
        card_values = {
            "Total Persistence Items": (str(len(self.report.items)), f"Last scan: {_display(self.report.completed_at)}"),
            "High-Risk Findings": (f"{critical} critical / {high} high", "Critical and high persistence findings requiring first review."),
            "New Since Baseline": (f"{added} added / {changed} changed", "Baseline comparison signals for persistence drift."),
            "Suspicious Targets": (f"{unsigned} unsigned / {temp_targets} temp / {missing_targets} missing", "Unsigned, temporary/shared, or missing targets."),
            "Rootkit Suspects": (
                "Unavailable" if self._rootkit_scan_error else str(rootkit["findings"]),
                self._rootkit_scan_error or f"{rootkit['high_findings']} high/critical rootkit-like indicator(s). Open Rootkits & Kernel Extensions for evidence.",
            ),
            "Risky Extensions": (
                "Unavailable" if self._rootkit_scan_error else str(rootkit["risky_extensions"]),
                self._rootkit_scan_error or f"{rootkit['risky_kernel_extensions']} kernel extension(s); {rootkit['extension_findings']} related suspect finding(s). Verify signature, Team ID, path, and approval.",
            ),
            "Scanner Coverage": (
                "Degraded" if scanner_errors or self._rootkit_scan_error else "Healthy",
                "Rootkit/extension review failed; inspect Diagnostics." if self._rootkit_scan_error else f"{len(scanner_errors)} scanner(s) need review." if scanner_errors else "All scanner coverage rows reported healthy or clean.",
            ),
        }
        for title, (value, detail) in card_values.items():
            value_label, detail_label = self.summary_cards[title]
            value_label.setText(value or "Not scanned")
            detail_label.setText(detail or "No additional detail.")
        self._fill_table(self.top_risks_table, self._top_risk_rows())
        item_by_id = {item.item_id: item for item in self.report.items}
        ranked = sorted(self.report.findings, key=lambda finding: item_by_id.get(finding.item_id).risk_score if item_by_id.get(finding.item_id) else 0, reverse=True)[:10]
        for row_index, finding in enumerate(ranked):
            first = self.top_risks_table.item(row_index, 0)
            if first is not None:
                first.setData(Qt.UserRole + 2, item_by_id.get(finding.item_id))
                first.setData(Qt.UserRole + 3, finding.finding_id)
        self._fill_table(self.mechanism_table, self._mechanism_rows())
        self._fill_table(self.dashboard_coverage_table, self._coverage_rows())

    def _rootkit_metrics(self) -> dict[str, int]:
        result = self.rootkit_result
        if result is None:
            return {"findings": 0, "high_findings": 0, "risky_extensions": 0, "risky_kernel_extensions": 0, "extension_findings": 0}
        risky_extensions = [
            item for item in result.extensions
            if item.risk_flags or item.signed_status in {"unsigned", "invalid"} or (item.loaded and not item.team_id and not item.bundle_id.startswith("com.apple."))
        ]
        return {
            "findings": len(result.findings),
            "high_findings": sum(finding.severity in {"high", "critical"} for finding in result.findings),
            "risky_extensions": len(risky_extensions),
            "risky_kernel_extensions": sum(item.type == "kernel_extension" for item in risky_extensions),
            "extension_findings": sum(finding.category in {"kernel_extension", "system_extension"} for finding in result.findings),
        }

    def _top_risk_rows(self) -> list[list[object]]:
        if self.report is None:
            return [["", "No elevated persistence risks detected.", "", "", "", "Run Persistence Scan"]]
        item_by_id = {item.item_id: item for item in self.report.items}
        findings = sorted(self.report.findings, key=lambda finding: item_by_id.get(finding.item_id).risk_score if item_by_id.get(finding.item_id) else 0, reverse=True)[:10]
        if not findings:
            return [["", "No elevated persistence risks detected.", "", "", "", "Continue routine monitoring."]]
        rows = []
        for index, finding in enumerate(findings, start=1):
            item = item_by_id.get(finding.item_id)
            removal = plan_removal(item) if item is not None else None
            action = "Review / Back Up and Remove…" if removal and removal.allowed else "Review details"
            rows.append([index, finding.severity, _short(item.label or item.name if item else finding.title, limit=52), item.mechanism if item else "Unknown", _short("; ".join(finding.evidence[:2]) or finding.description, limit=90), action])
        return rows

    def _mechanism_rows(self) -> list[list[object]]:
        if self.report is None or not self.report.items:
            return [["No items found", 0, 0, "Unknown"]]
        item_counts = Counter(item.mechanism for item in self.report.items)
        finding_counts = Counter()
        highest: dict[str, tuple[int, str]] = {}
        item_by_id = {item.item_id: item for item in self.report.items}
        for item in self.report.items:
            highest[item.mechanism] = max(highest.get(item.mechanism, (-1, "INFO")), (item.risk_score, item.risk_level), key=lambda pair: pair[0])
        for finding in self.report.findings:
            item = item_by_id.get(finding.item_id)
            if item:
                finding_counts[item.mechanism] += 1
        return [[mechanism, count, finding_counts.get(mechanism, 0), highest.get(mechanism, (0, "INFO"))[1]] for mechanism, count in sorted(item_counts.items())]

    def _coverage_rows(self) -> list[list[object]]:
        if self.report is None or not self.report.coverage:
            return [["No scanner data", "Not scanned", 0, 0, "Not scanned", "Run Persistence Scan"]]
        result_by_id = {result.scanner_id: result for result in self.report.scanner_results}
        rows = []
        for coverage in self.report.coverage:
            scanner_id = str(coverage.get("scanner_id", "Unknown"))
            result = result_by_id.get(scanner_id)
            warnings = list(getattr(result, "warnings", []) or [])
            errors = list(getattr(result, "errors", []) or [])
            status = str(coverage.get("coverage_status", "Unknown"))
            if errors:
                cause = "Failed: " + "; ".join(errors)
                next_step = "Resolve collector errors and permissions, validate missed locations manually, then rerun."
            elif warnings:
                cause = "Partial/degraded: " + "; ".join(warnings)
                next_step = "Review limitations, obtain approved read access where appropriate, validate gaps, then rerun."
            elif status.lower() in {"healthy", "clean", "pass", "passed", "complete"}:
                cause = f"Passed: completed without scanner warnings/errors; {coverage.get('item_count', 0)} item(s), {coverage.get('finding_count', 0)} finding(s)."
                next_step = "Investigate findings and keep evidence current. Collection pass does not prove absence of compromise."
            else:
                cause = f"{status}: no detailed scanner cause was supplied."
                next_step = "Review Diagnostics and validate this surface manually before assigning pass."
            rows.append([scanner_id, status, coverage.get("item_count", 0), coverage.get("finding_count", 0), cause, next_step])
        return rows

    def _top_risk_clicked(self, row: int, column: int) -> None:
        if column == self.top_risks_table.columnCount() - 1:
            action_item = self.top_risks_table.item(row, column)
            if action_item is not None:
                self._show_remediation_menu(self.top_risks_table, self.top_risks_table.visualItemRect(action_item).center())
        else:
            self._open_top_risk(row)

    def _open_top_risk(self, row: int) -> None:
        first = self.top_risks_table.item(row, 0)
        finding_id = first.data(Qt.UserRole + 3) if first is not None else None
        if not finding_id:
            return
        self.tabs.setCurrentIndex(2)
        for finding_row, payload in enumerate(self._finding_detail_payloads):
            finding = payload.get("finding")
            if finding is not None and finding.finding_id == finding_id:
                self.findings_table.selectRow(finding_row)
                self.findings_table.scrollToItem(self.findings_table.item(finding_row, 0))
                self._show_selected_finding_detail(finding_row, 0, -1, -1)
                break

    def _open_coverage_detail(self, row: int) -> None:
        scanner = self.dashboard_coverage_table.item(row, 0)
        self.tabs.setCurrentIndex(6)
        if scanner is None:
            return
        for coverage_row in range(self.coverage_table.rowCount()):
            candidate = self.coverage_table.item(coverage_row, 0)
            if candidate is not None and candidate.text() == scanner.text():
                self.coverage_table.selectRow(coverage_row)
                self.coverage_table.scrollToItem(candidate)
                break

    def _item_for_finding(self, finding) -> Any:
        if self.report is None:
            return None
        return next((item for item in self.report.items if item.item_id == finding.item_id), None)

    def _finding_row(self, finding) -> dict[str, Any]:
        item = self._item_for_finding(finding)
        target = item.executable_path or item.program or item.path if item else ""
        evidence = "; ".join(finding.evidence[:3]) or finding.description
        return {
            "severity": finding.severity,
            "risk": item.risk_level if item else finding.severity,
            "risk_score": item.risk_score if item else "",
            "confidence": finding.confidence,
            "mechanism": item.mechanism if item else "Unknown",
            "label": item.label or item.name if item else finding.title,
            "target": target,
            "owner": f"{item.owner}:{item.group}".strip(":") if item else "Unknown",
            "signature": item.signed_status if item else "Unknown",
            "baseline": item.baseline_status if item else "Unknown",
            "why": evidence,
            "action": finding.suggested_fix,
            "first_seen": item.first_seen if item else finding.created_at,
            "status": "Open",
            "cvss": finding.cvss_score,
            "mitre": ", ".join(finding.mitre_mapping) or "Unmapped",
            "frameworks": ", ".join([*finding.nist_mapping, *finding.cis_mapping]),
            "scanner": item.source_scanner if item else "Unknown",
            "finding": finding,
            "item": item,
            "search": " ".join([finding.title, finding.description, evidence, target, item.owner if item else "", item.mechanism if item else "", item.source_scanner if item else ""]),
        }

    def _inventory_row(self, item) -> dict[str, Any]:
        return {
            "mechanism": item.mechanism,
            "label": item.label or item.name,
            "path": item.path,
            "target": item.executable_path or item.program,
            "loaded": item.loaded,
            "disabled": item.disabled,
            "run_at_load": item.run_at_load,
            "keep_alive": item.keep_alive,
            "owner": f"{item.owner}:{item.group}".strip(":") or "Unknown",
            "permissions": item.permissions or "Unknown",
            "signature": item.signed_status or "Unknown",
            "trust": item.trust_label or "Unknown",
            "trust_score": item.trust_score,
            "risk": item.risk_level or "Unknown",
            "risk_score": item.risk_score,
            "baseline": item.baseline_status or "Unknown",
            "scanner": item.source_scanner or "Unknown",
            "developer": item.developer_identity or "Unknown",
            "team_id": item.team_id or "Unknown",
            "mitre": ", ".join(item.mitre_techniques) or "Unmapped",
            "first_seen": item.first_seen,
            "last_seen": item.last_seen,
            "analyst_status": item.analyst_status,
            "item": item,
            "search": " ".join([item.label, item.name, item.path, item.executable_path, item.program, item.owner, item.mechanism, item.source_scanner, " ".join(item.evidence)]),
        }

    def _populate_filters(self) -> None:
        def reset(combo: QComboBox, values: list[str], first: str) -> None:
            current = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem(first)
            for value in sorted({str(v) for v in values if str(v).strip()}):
                combo.addItem(value)
            if current:
                index = combo.findText(current)
                combo.setCurrentIndex(index if index >= 0 else 0)
            combo.blockSignals(False)

        reset(self.severity_filter, [row["severity"] for row in self._all_finding_rows], "All severities")
        reset(self.risk_filter, [row["risk"] for row in self._all_inventory_rows + self._all_finding_rows], "All risks")
        reset(self.mechanism_filter, [row["mechanism"] for row in self._all_inventory_rows + self._all_finding_rows], "All mechanisms")
        reset(self.baseline_filter, [row["baseline"] for row in self._all_inventory_rows + self._all_finding_rows], "All baseline states")
        reset(self.signature_filter, [row["signature"] for row in self._all_inventory_rows + self._all_finding_rows], "All signatures")
        reset(self.trust_filter, [row["trust"] for row in self._all_inventory_rows], "All trust labels")
        reset(self.scanner_filter, [row["scanner"] for row in self._all_inventory_rows + self._all_finding_rows], "All scanner sources")

    def _apply_filters(self) -> None:
        query = self.search_box.text().strip().lower()

        def selected(combo: QComboBox, prefix: str) -> str:
            text = combo.currentText()
            return "" if text.startswith("All ") else text

        severity = selected(self.severity_filter, "All severities")
        risk = selected(self.risk_filter, "All risks")
        mechanism = selected(self.mechanism_filter, "All mechanisms")
        baseline = selected(self.baseline_filter, "All baseline states")
        signature = selected(self.signature_filter, "All signatures")
        trust = selected(self.trust_filter, "All trust labels")
        scanner = selected(self.scanner_filter, "All scanner sources")

        inventory = [
            row
            for row in self._all_inventory_rows
            if (not query or query in row["search"].lower())
            and (not risk or row["risk"] == risk)
            and (not mechanism or row["mechanism"] == mechanism)
            and (not baseline or row["baseline"] == baseline)
            and (not signature or row["signature"] == signature)
            and (not trust or row["trust"] == trust)
            and (not scanner or row["scanner"] == scanner)
        ]
        findings = [
            row
            for row in self._all_finding_rows
            if (not query or query in row["search"].lower())
            and (not severity or row["severity"] == severity)
            and (not risk or row["risk"] == risk)
            and (not mechanism or row["mechanism"] == mechanism)
            and (not baseline or row["baseline"] == baseline)
            and (not signature or row["signature"] == signature)
            and (not scanner or row["scanner"] == scanner)
        ]
        self._fill_inventory(inventory)
        self._fill_findings(findings)

    def _fill_inventory(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            self._fill_table(self.inventory_table, [["No persistence inventory items match the current filters.", "", "", "", "", "", "", "", "", "", "", "Unknown", "Unknown", "Unknown"]])
            return
        self._fill_table(
            self.inventory_table,
            [[row["mechanism"], row["label"], row["path"], row["target"], row["loaded"], row["disabled"], row["run_at_load"], row["keep_alive"], row["owner"], row["permissions"], row["signature"], row["trust"], row["risk"], row["baseline"], row["developer"], row["team_id"], row["mitre"], row["first_seen"], row["last_seen"], row["analyst_status"], self._removal_label(row.get("item"))] for row in rows],
        )
        for row_index, row in enumerate(rows):
            first = self.inventory_table.item(row_index, 0)
            if first is not None:
                persistence_item = row.get("item")
                # Preserve the original table contract for consumers that use
                # UserRole while retaining the remediation-specific role.
                first.setData(Qt.UserRole, persistence_item)
                first.setData(Qt.UserRole + 2, persistence_item)

    def _fill_findings(self, rows: list[dict[str, Any]]) -> None:
        self._finding_detail_payloads = rows
        if not rows:
            self._fill_table(self.findings_table, [["No persistence findings detected.", "", "", "", "", "", "", "", "", "", "", "", ""]])
            self.finding_detail.setPlainText("No persistence findings detected.")
            return
        self._fill_table(
            self.findings_table,
            [[row["severity"], row["risk"], row["confidence"], row["mechanism"], row["label"], row["target"], row["owner"], row["signature"], row["baseline"], _short(row["why"], limit=95), _short(row["action"], limit=95), row["first_seen"], row["status"], row["cvss"], row["mitre"], row["frameworks"], self._removal_label(row.get("item"))] for row in rows],
        )
        for row_index in range(len(rows)):
            first_item = self.findings_table.item(row_index, 0)
            if first_item is not None:
                first_item.setData(Qt.UserRole + 1, row_index)
                first_item.setData(Qt.UserRole + 2, rows[row_index].get("item"))

    def _show_remediation_menu(self, table: QTableWidget, position) -> None:
        row = table.rowAt(position.y())
        first = table.item(row, 0) if row >= 0 else None
        persistence_item = first.data(Qt.UserRole + 2) if first is not None else None
        if not isinstance(persistence_item, PersistenceItem):
            return
        plan = plan_removal(persistence_item)
        menu = QMenu(table)
        suffix = Path(plan.path).suffix.lower()
        if suffix == ".plist":
            action_text = "Unload / Stop Process and Quarantine…"
        elif suffix == ".kext":
            action_text = "Unload Extension and Quarantine…"
        else:
            action_text = "Back Up and Quarantine…"
        action = menu.addAction(action_text)
        action.setEnabled(plan.allowed)
        action.setToolTip(plan.impact if plan.allowed else plan.refusal_reason)
        trust_action = menu.addAction("Mark Trusted…")
        trust_action.setEnabled(bool(persistence_item.target_hash_sha256))
        trust_action.setToolTip("Records a user disposition bound to hash, canonical path, bundle ID, and Team ID. Signing status remains unchanged.")
        selected = menu.exec(table.viewport().mapToGlobal(position))
        if selected == action:
            self._confirm_removal(persistence_item)
        elif selected == trust_action:
            reason, accepted = QInputDialog.getText(self, "Mark Persistence Item Trusted", "Reason for trusting this exact artifact:")
            if accepted and reason.strip():
                try:
                    self.trust_store.trust(persistence_item, user=getpass.getuser(), reason=reason)
                    QMessageBox.information(self, "Trust Disposition Recorded", "Trust was bound to the current hash and identity. A changed artifact will require review again.")
                    self.run_scan()
                except Exception as exc:
                    QMessageBox.warning(self, "Trust Was Not Recorded", str(exc))

    def _removal_label(self, item: Any) -> str:
        if not isinstance(item, PersistenceItem):
            return "Not applicable"
        plan = plan_removal(item)
        if plan.allowed:
            if item.mechanism == "kernel_extension" or Path(plan.path).suffix.lower() == ".kext":
                return "Quarantine / Forced Unload…"
            if Path(plan.path).suffix.lower() == ".plist":
                return "Unload / Stop / Quarantine…"
            return "Back Up and Quarantine…"
        if "Apple platform" in plan.refusal_reason:
            return "Protected system component"
        return "Removal unavailable"

    def _remediation_cell_clicked(self, table: QTableWidget, row: int, column: int) -> None:
        header = table.horizontalHeaderItem(column)
        if header is None or header.text() != "Removal":
            return
        first = table.item(row, 0)
        persistence_item = first.data(Qt.UserRole + 2) if first is not None else None
        if isinstance(persistence_item, PersistenceItem):
            plan = plan_removal(persistence_item)
            if not plan.allowed:
                QMessageBox.warning(
                    self,
                    "Protected or Unsupported Component",
                    "This item cannot be removed by MSAA. It may be a critical macOS component or outside the bounded remediation locations.\n\n"
                    f"Reason: {plan.refusal_reason}\n\nNo files were changed.",
                )
                return
        cell = table.item(row, column)
        if cell is not None:
            self._show_remediation_menu(table, table.visualItemRect(cell).center())

    def _confirm_removal(self, item: PersistenceItem) -> None:
        plan = plan_removal(item)
        if not plan.allowed:
            QMessageBox.warning(self, "Removal Not Available", plan.refusal_reason)
            return
        system_warning = (
            "CRITICAL SYSTEM TASK WARNING: this is a system-wide task. Removing it may affect every user or make required security, network, driver, or startup functions unavailable. Verify ownership and incident authority before continuing.\n\n"
            if plan.administrator_required else ""
        )
        warning = (
            "Caution: removing persistence can stop applications, security software, drivers, networking, or login services from working.\n\n"
            f"Artifact: {plan.path}\nImpact: {plan.impact}\n"
            f"Administrator required: {'yes' if plan.administrator_required else 'no'}\n\n"
            f"{system_warning}"
            "MSAA will preserve a restorable backup and evidence manifest before moving the original into quarantine.\n"
            f"Removal-resistance flags: {', '.join(plan.tamper_flags) if plan.tamper_flags else 'none detected'}\n"
            f"Referenced payload: {plan.referenced_payload or 'none safely identified'}"
        )
        answer = QMessageBox.warning(
            self, "Potentially Harmful Removal", warning,
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        confirmation, accepted = QInputDialog.getText(self, "Confirm Persistence Removal", "Type REMOVE to continue:")
        if not accepted or confirmation.strip() != "REMOVE":
            return
        try:
            include_payload = False
            force_stop = False
            force_unload_extension = False
            incident_reference = ""
            if plan.referenced_payload:
                payload_answer = QMessageBox.warning(
                    self,
                    "Also Quarantine Referenced Executable?",
                    "The plist points to the executable below. Quarantining it is a separate, higher-impact action. "
                    "MSAA will refuse operating-system paths, symlinks, directories, or a target whose recorded hash changed.\n\n"
                    f"{plan.referenced_payload}",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                include_payload = payload_answer == QMessageBox.Yes
            if Path(plan.path).suffix.lower() == ".plist":
                force_answer = QMessageBox.warning(
                    self,
                    "Permit Identity-Bound Force Stop?",
                    "If graceful launchd bootout fails, MSAA can request SIGKILL for this exact validated launchd domain and label, then retry bootout. "
                    "This can interrupt work and should be used only during an authorized incident response. No PID or process-name matching is used.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                force_stop = force_answer == QMessageBox.Yes
            if item.mechanism == "kernel_extension" or Path(plan.path).suffix.lower() == ".kext":
                force_answer = QMessageBox.critical(
                    self,
                    "Confirmed-Malicious Kernel Extension",
                    "Choose Yes only when an authorized responder has determined beyond reasonable doubt that this exact third-party kernel extension is malicious.\n\n"
                    f"Bundle ID: {plan.label}\nPath: {plan.path}\n\n"
                    "MSAA will attempt an identity-bound kmutil unload and quarantine the on-disk bundle. A failed unload means the loaded kernel code can remain active until restart. "
                    "Apple/SIP-protected extensions cannot be bypassed.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if force_answer == QMessageBox.Yes:
                    incident_reference, accepted = QInputDialog.getText(
                        self, "Incident Authorization Required", "Incident or change record reference:"
                    )
                    if not accepted or not incident_reference.strip():
                        return
                    phrase = f"FORCE QUARANTINE {plan.label}"
                    forced_confirmation, accepted = QInputDialog.getText(
                        self, "Confirm Forced Kernel Extension Removal", f"Type exactly: {phrase}"
                    )
                    if not accepted or forced_confirmation.strip() != phrase:
                        return
                    force_unload_extension = True
            result = quarantine_removal(
                item,
                include_referenced_payload=include_payload,
                force_stop_launchd_job=force_stop,
                force_unload_extension=force_unload_extension,
                incident_reference=incident_reference,
            )
            extension_unload = result.get("extension_unload", {})
            restart_note = (
                "\n\nThe extension may remain loaded until macOS is restarted. Preserve the evidence manifest and follow the vendor/MDM uninstall procedure when one exists."
                if item.mechanism in {"kernel_extension", "system_extension", "driver_extension"} or Path(plan.path).suffix.lower() in {".kext", ".systemextension", ".dext"} else ""
            )
            if isinstance(extension_unload, dict) and extension_unload.get("attempted"):
                restart_note += (
                    "\nForced unload succeeded for the exact bundle ID."
                    if extension_unload.get("success") else
                    "\nForced unload did not succeed; treat the host as still affected, isolate it under incident policy, and restart through the authorized response workflow."
                )
            QMessageBox.information(self, "Artifact Quarantined", f"The artifact was backed up and quarantined.\n\nManifest: {result['manifest_path']}{restart_note}")
            self.run_scan()
        except Exception as exc:
            QMessageBox.warning(self, "Removal Did Not Run", str(exc))

    def _chain_view_html(self) -> str:
        if self.report is None:
            return ""
        sections = []
        chains = build_chain_view(self.report.items, self.report.findings)
        item_by_id = {item.item_id: item for item in self.report.items}
        findings_by_item: dict[str, list[Any]] = {}
        for finding in self.report.findings:
            findings_by_item.setdefault(finding.item_id, []).append(finding)
        for chain in chains:
            item = item_by_id.get(str(chain.get("item_id", "")))
            risk = risk_badge_html(item.risk_level, item.risk_score) if item is not None else risk_badge_html("unknown")
            trust = risk_badge_html(item.trust_label, item.trust_score) if item is not None else risk_badge_html("unknown")
            item_findings = findings_by_item.get(item.item_id, []) if item is not None else []
            confidence_values = {"high": 90, "medium": 65, "low": 35}
            confidence_score = max((confidence_values.get(str(finding.confidence).lower(), 25) for finding in item_findings), default=25)
            evidence = []
            for finding in item_findings:
                evidence.extend(str(value) for value in finding.evidence)
            if item is not None:
                evidence.extend(str(value) for value in item.evidence)
            evidence = list(dict.fromkeys(value for value in evidence if value))
            rating = str(getattr(item, "risk_level", "unknown") or "unknown").upper()
            score = int(getattr(item, "risk_score", 0) or 0)
            if rating in {"INFO", "LOW"}:
                why_rating = "No elevated detector combination was established. The observed item may be legitimate, signed, expected, or unchanged from baseline."
                disposition = "Routine review/monitoring is appropriate. Do not quarantine solely because persistence exists; verify publisher, path, signature, baseline, and business owner first."
            elif rating == "MEDIUM":
                why_rating = "One or more suspicious or uncertain signals require analyst verification, but the evidence does not yet establish malicious persistence."
                disposition = "Investigate ownership, signature, hash, target, and baseline drift. Quarantine only after it is confirmed unauthorized or additional malicious evidence raises confidence."
            else:
                why_rating = "Multiple high-impact signals or a strong persistence indicator raised the rating and warrants prompt incident-response review."
                disposition = "Preserve evidence first. Back up and quarantine only when the artifact is verified unauthorized/malicious and removal is approved. Protected Apple components must not be removed in-app."
            relationships = "".join(
                f"<li><strong>{html.escape(str(rel.get('type', '')).replace('_', ' ').title())}:</strong> {html.escape(str(rel.get('value', '')))}</li>"
                for rel in chain.get("relationships", [])
                if isinstance(rel, dict)
            )
            sections.append(
                f"<section><h3>{risk} {trust} {html.escape(str(chain.get('item_id', '')))}</h3>"
                f"<p><strong>Risk score:</strong> {score}/100 ({html.escape(rating)}) &nbsp; "
                f"<strong>Evidence confidence:</strong> {confidence_score}/100</p>"
                f"<p><strong>Why this rating:</strong> {html.escape(why_rating)}</p>"
                f"<p><strong>Concern / quarantine guidance:</strong> {html.escape(disposition)}</p>"
                f"<p><strong>Rating evidence:</strong> {html.escape('; '.join(evidence[:8]) if evidence else 'No elevated finding evidence was produced; validate coverage limitations before treating this as conclusively safe.')}</p>"
                f"<h4>Observed chain</h4><ul>{relationships}</ul></section>"
            )
        return "<html><body>" + "".join(sections) + "</body></html>"

    def _fill_table(self, table: QTableWidget, rows: list[list[object]]) -> None:
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        headers = [table.horizontalHeaderItem(index).text() for index in range(table.columnCount())]
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                header = headers[column].lower() if column < len(headers) else ""
                text = _display(value)
                if header in {"path", "target", "target path", "recommended action", "why flagged"}:
                    text = _short(value, limit=90)
                item = QTableWidgetItem(text)
                item.setToolTip(_display(value))
                if header in {"risk", "severity"}:
                    score = row[headers.index("Risk Score")] if "Risk Score" in headers and header == "risk" else None
                    apply_risk_item_style(item, value, score, text=display_risk_label(value, score))
                elif header == "risk score":
                    risk_value = row[headers.index("Risk")] if "Risk" in headers else None
                    apply_risk_item_style(item, risk_value, value, text=str(value if value not in {None, ''} else "UNKNOWN"))
                elif header == "trust":
                    score = row[headers.index("Trust Score")] if "Trust Score" in headers else None
                    apply_risk_item_style(item, value, score, text=display_risk_label(value, score))
                elif header == "trust score":
                    trust_value = row[headers.index("Trust")] if "Trust" in headers else None
                    apply_risk_item_style(item, trust_value, value, text=str(value if value not in {None, ''} else "UNKNOWN"))
                elif header == "confidence":
                    confidence_label = str(value or "unknown").lower()
                    style_label = "trusted" if confidence_label == "high" else "medium" if confidence_label == "medium" else "unknown"
                    apply_risk_item_style(item, style_label, text=str(value or "UNKNOWN").upper())
                elif header in {"baseline", "baseline status", "status"}:
                    apply_risk_item_style(item, value or "unknown", text=str(value or "UNKNOWN").upper())
                elif header in {"loaded", "disabled", "runatload", "keepalive"}:
                    item.setText(_display(value))
                    item.setTextAlignment(Qt.AlignCenter)
                table.setItem(row_index, column, item)
        table.setSortingEnabled(True)
        table.resizeColumnsToContents()

    def _show_selected_finding_detail(self, current_row: int, _current_column: int, _previous_row: int, _previous_column: int) -> None:
        payload_index = current_row
        first_item = self.findings_table.item(current_row, 0) if current_row >= 0 else None
        if first_item is not None and first_item.data(Qt.UserRole + 1) is not None:
            payload_index = int(first_item.data(Qt.UserRole + 1))
        if payload_index < 0 or payload_index >= len(self._finding_detail_payloads):
            self.finding_detail.setPlainText("Select a persistence finding to view details.")
            return
        row = self._finding_detail_payloads[payload_index]
        finding = row.get("finding")
        item = row.get("item")
        if finding is None:
            self.finding_detail.setPlainText("Select a persistence finding to view details.")
            return
        details = [
            f"Title: {finding.title}",
            f"Severity: {finding.severity}",
            f"Risk score: {_display(getattr(item, 'risk_score', ''), unavailable='Unknown')}",
            f"Confidence: {finding.confidence}",
            f"Mechanism: {_display(getattr(item, 'mechanism', ''), unavailable='Unknown')}",
            f"Full path: {_display(getattr(item, 'path', ''), unavailable='Unknown')}",
            f"Program: {_display(getattr(item, 'program', ''), unavailable='Unavailable')}",
            f"ProgramArguments: {_display(getattr(item, 'program_arguments', []), unavailable='Unavailable')}",
            f"Owner / permissions: {_display(row.get('owner'))} / {_display(getattr(item, 'permissions', ''), unavailable='Unknown')}",
            f"Signature status: {_display(row.get('signature'))}",
            f"Baseline status: {_display(row.get('baseline'))}",
            "",
            "Risk factors:",
            *[f"- {evidence}" for evidence in getattr(finding, "evidence", [])],
            "",
            f"Why it matters: {finding.why_it_matters}",
            f"False positive notes: {finding.false_positive_notes}",
            f"Recommended verification: {_display(getattr(item, 'recommended_verification', ''), unavailable='Review owner, target, signature, permissions, and baseline history.')}",
            f"Suggested fix: {finding.suggested_fix}",
            f"CVSS-aligned review score: {finding.cvss_score}",
            f"MITRE / NIST: {_display(finding.mitre_mapping)} | {_display(finding.nist_mapping)}",
            f"CIS: {_display(finding.cis_mapping)}",
        ]
        self.finding_detail.setPlainText("\n".join(details))

    def create_baseline(self) -> None:
        if self.report is None:
            self.run_scan()
        if self.report is None:
            return
        reasons = insecure_baseline_reasons(self.report, self.rootkit_result)
        acknowledgement = ""
        if reasons:
            warning = (
                f"{INSECURE_BASELINE_DISCLAIMER}\n\nCurrent blocking evidence:\n- "
                + "\n- ".join(reasons)
                + "\n\nCancel and contact local IT is the recommended action. No baseline has been created."
            )
            QMessageBox.critical(self, "MSAA Advises Against This Trusted Baseline", warning, QMessageBox.Ok)
            acknowledgement, accepted = QInputDialog.getText(
                self,
                "Accept Full Responsibility",
                f"To proceed against MSAA advice, type {RISK_ACCEPTANCE_PHRASE} exactly and press Enter:",
            )
            acknowledgement = acknowledgement.strip()
            if not accepted or acknowledgement != RISK_ACCEPTANCE_PHRASE:
                self.baseline_text.setPlainText("Trusted baseline refused. The insecure-system disclaimer was not accepted. Contact local IT or an authorized security team.")
                return
        path = self.baselines.create_baseline(
            self.baseline_name.text().strip() or "trusted", self.report.items,
            risk_reasons=reasons, acknowledgement=acknowledgement, acknowledged_by=getpass.getuser(),
        )
        self.baseline_text.setPlainText(f"Created baseline: {path}")

    def compare_baseline(self) -> None:
        if self.report is None:
            self.run_scan()
        if self.report is None:
            return
        comparison = self.baselines.compare_baseline(self.baseline_name.text().strip() or "trusted", self.report.items)
        self.baseline_text.setPlainText(json.dumps(comparison, indent=2, sort_keys=True))

    def export_report(self, fmt: str = "html") -> None:
        if self.report is None:
            self.run_scan()
        if self.report is None:
            return
        suffix = "zip" if fmt == "bundle" else ("md" if fmt == "md" else fmt)
        default = get_reports_dir() / f"persistence_intelligence_{self.report.scan_id}.{suffix}"
        path, _ = QFileDialog.getSaveFileName(self, "Export Persistence Intelligence Report", str(default), "All Files (*)")
        if not path:
            return
        output = Path(path)
        try:
            if fmt == "txt":
                saved = export_persistence_report_text(self.report, output)
            elif fmt == "csv":
                saved = export_persistence_report_csv(self.report, output)
            elif fmt == "json":
                saved = export_persistence_report_json(self.report, output)
            elif fmt == "md":
                saved = export_persistence_report_markdown(self.report, output)
            elif fmt == "pdf":
                saved = export_persistence_report_pdf(self.report, output)
            elif fmt == "docx":
                saved = export_persistence_report_docx(self.report, output)
            elif fmt == "xlsx":
                saved = export_persistence_report_excel(self.report, output)
            elif fmt == "bundle":
                saved = export_persistence_incident_bundle(self.report, output)
            else:
                saved = export_persistence_report_html(self.report, output)
        except Exception as exc:
            QMessageBox.warning(self, "Report Export Failed", str(exc))
            return
        QMessageBox.information(self, "Persistence Report Exported", f"Saved report to:\n{saved}")

    def run_rootkit_review(self, *, system_integrity: bool = True, extensions: bool = True, ports: bool = True, correlate: bool = True, dylib_hijacks: bool = True) -> None:
        try:
            self.rootkit_summary.setText("Running read-only Rootkit & Advanced Persistence review...")
            self._rootkit_scan_error = ""
            self.rootkit_result = run_rootkit_review(
                mode="quick",
                local_only=True,
                system_integrity=system_integrity,
                extensions=extensions,
                ports=ports,
                correlate=correlate,
                dylib_hijacks=dylib_hijacks,
            )
            self._render_rootkit_result()
            self._record_rootkit_security_events()
            if self.report is not None:
                self._render_report()
        except Exception as exc:
            self._rootkit_scan_error = f"{type(exc).__name__}: {exc}"
            self.rootkit_summary.setText("Rootkit & Advanced Persistence review failed. No changes were made.")
            QMessageBox.warning(self, "Rootkit Review Failed", str(exc))

    def _record_rootkit_security_events(self) -> None:
        result = self.rootkit_result
        db = getattr(self.window(), "db", None)
        if result is None or db is None:
            return
        event_types = {
            "dynamic_library_hijack": "dylib_hijack_detected",
            "kernel_extension": "suspicious_kernel_extension_detected",
            "system_extension": "suspicious_system_extension_detected",
        }
        for finding in result.findings:
            if finding.severity not in {"high", "critical"}:
                continue
            event_type = event_types.get(finding.category, "rootkit_suspect_detected")
            timestamp = utc_now_iso()
            evidence = "; ".join(finding.evidence[:8])
            related_path = next((item.split(": ", 1)[1] for item in finding.evidence if item.startswith(("Executable: ", "Candidate: ", "found on disk: "))), "")
            event = BackgroundMonitorEvent(
                event_id=f"rootkit-review-{uuid4().hex}",
                timestamp=timestamp,
                event_type=event_type,
                severity=finding.severity,
                source="rootkit_advanced_persistence_review",
                evidence=evidence,
                confidence=finding.confidence,
                recommendation=finding.recommended_fix,
                metadata_json=json.dumps(finding.to_dict(), sort_keys=True),
                related_path=related_path,
                first_seen=timestamp,
                last_seen=timestamp,
                current_state="requires advanced persistence review",
            )
            db.record_background_monitor_event(event, dedupe_window_seconds=600)

    def _render_rootkit_result(self) -> None:
        result = self.rootkit_result
        if result is None:
            return
        high = sum(1 for finding in result.findings if finding.severity in {"high", "critical"})
        self.rootkit_summary.setText(
            f"Review completed: findings={len(result.findings)} | high/critical={high} | "
            f"extensions={len(result.extensions)} | ports={len(result.port_findings)} | mismatches={len(result.visibility_mismatches)}. "
            "This is a suspect review, not a rootkit confirmation."
        )
        posture = result.posture
        self._fill_table(
            self.rootkit_posture_table,
            [
                self._posture_explanation("SIP", posture.sip_status, posture.csrutil_output),
                self._posture_explanation("Authenticated Root", posture.authenticated_root_status, ""),
                self._posture_explanation("Signed System Volume", posture.ssv_status, ""),
                self._posture_explanation("Gatekeeper", posture.gatekeeper_status, posture.spctl_output),
                self._posture_explanation("FileVault", posture.filevault_status, ""),
                self._posture_explanation("Secure Boot / Reduced Security", posture.secure_boot_status, "Reduced security detected" if posture.reduced_security_detected else ""),
                self._posture_explanation("Boot Args", posture.boot_args or "None observed", "; ".join(posture.warnings[:4])),
            ],
        )
        self._fill_table(
            self.rootkit_extension_table,
            [
                [item.type, item.bundle_id, item.team_id or "Unknown", item.loaded, item.path, item.signed_status, "; ".join(item.risk_flags), self._removal_label(self._rootkit_extension_remediation_item(item))]
                for item in result.extensions[:250]
            ]
            or [["No extension inventory items found.", "", "", "", "", "", "", ""]],
        )
        for row_index, extension in enumerate(result.extensions[:250]):
            first = self.rootkit_extension_table.item(row_index, 0)
            if first is not None:
                first.setData(Qt.UserRole + 2, self._rootkit_extension_remediation_item(extension))
        self._fill_table(
            self.rootkit_ports_table,
            [
                [item.protocol, item.port, item.bind_address, item.pid, item.process_owner, item.lsof_seen, item.netstat_seen, item.nc_seen, item.visibility_status, item.severity]
                for item in result.port_findings[:250]
            ]
            or [["No local listener visibility findings.", "", "", "", "", "", "", "", "", ""]],
        )
        self._fill_table(
            self.rootkit_findings_table,
            [
                [finding.severity, finding.confidence, finding.category, finding.title, "; ".join(finding.evidence[:3]), finding.recommended_fix, self._removal_label(self._rootkit_finding_remediation_item(finding))]
                for finding in result.findings
            ]
            or [["info", "low", "unknown", "No rootkit-like suspect findings produced.", "No correlated suspect indicators.", "Continue routine monitoring.", "Not applicable"]],
        )
        for row_index, finding in enumerate(result.findings):
            first = self.rootkit_findings_table.item(row_index, 0)
            if first is not None:
                first.setData(Qt.UserRole + 2, self._rootkit_finding_remediation_item(finding))

    def _posture_explanation(self, control: str, status: Any, evidence: str) -> list[str]:
        definitions = {
            "SIP": "System Integrity Protection restricts even the root account from modifying protected macOS files, processes, and security-sensitive locations.",
            "Authenticated Root": "Authenticated Root verifies that the operating-system volume matches Apple-signed content before macOS trusts and uses it.",
            "Signed System Volume": "The Signed System Volume seals macOS system files with cryptographic hashes so unauthorized changes can be detected and rejected.",
            "Gatekeeper": "Gatekeeper checks downloaded applications for an identified developer signature, notarization, and known security-policy violations before launch.",
            "FileVault": "FileVault encrypts the startup disk so data is not readable without an authorized login or recovery method when the Mac is powered off.",
            "Secure Boot / Reduced Security": "Secure Boot verifies trusted operating-system software during startup; Reduced Security permits exceptions that can expand kernel or extension risk.",
            "Boot Args": "Boot arguments alter low-level startup and kernel behavior. Unauthorized diagnostic or security-weakening arguments can reduce macOS protections.",
        }
        value = str(status or "unknown")
        normalized = value.lower()
        passing = normalized in {"enabled", "active", "enforced", "on", "full", "full security", "sealed", "verified"}
        unknown = normalized in {"", "unknown", "unavailable", "not checked", "unsupported"}
        if control == "Boot Args" and value == "None observed":
            passing, unknown = True, False
        if passing:
            why = f"Pass: {control} is reported as {value}. No weakening condition was reported by this collector."
            action = "Retain this setting, keep macOS updated, and rerun the review after boot-policy or management changes."
        elif unknown:
            why = f"Not passing evidence: {control} could not be conclusively verified. Unknown is never treated as compliant."
            action = "Review Diagnostics, confirm the scan has approved permissions, and verify the setting locally or through authorized MDM evidence before marking it pass."
        else:
            why = f"Needs remediation: {control} is reported as {value}, which does not match the expected protected posture."
            action = "Use the organization-approved macOS Recovery or MDM workflow and Apple-documented controls; record authorization and evidence, restart if required, then rerun this review."
        if control == "SIP":
            action += " For SIP, an authorized administrator must enable SIP from macOS Recovery with csrutil, restart macOS, and confirm `csrutil status` reports enabled. Do not disable SIP to remove a finding."
        elif control == "Authenticated Root":
            action += " Keep authenticated-root enforcement enabled; reversing a custom disabled state requires the authorized Recovery workflow and may require restoring/sealing the system volume."
        elif control == "Signed System Volume":
            action += " Apply signed Apple updates or an authorized macOS reinstall if the sealed system volume cannot be verified."
        elif control == "Gatekeeper":
            action += " Restore Gatekeeper assessment with approved system policy/MDM settings and verify with spctl; do not bypass it globally."
        elif control == "FileVault":
            action += " Enable FileVault through System Settings or approved MDM escrow. Never place a recovery key in MSAA evidence."
        elif control == "Secure Boot / Reduced Security":
            action += " Restore Full Security in Startup Security Utility when compatible with approved software; document any required exception."
        elif control == "Boot Args" and not passing:
            action += " Review each boot argument with the system owner and remove only unauthorized security-weakening arguments through approved NVRAM/MDM procedures."
        return [control, definitions.get(control, "A macOS platform protection reviewed as part of system-integrity posture."), value, evidence or "No additional collector output.", why, action]

    def _rootkit_extension_remediation_item(self, extension: Any) -> PersistenceItem | None:
        if not getattr(extension, "path", ""):
            return None
        return PersistenceItem.create(
            "system_extension" if "system" in extension.type.lower() else "driver_extension" if "driver" in extension.type.lower() else "kernel_extension",
            extension.path,
            label=extension.bundle_id,
            signed_status=extension.signed_status,
            team_id=extension.team_id,
            loaded=extension.loaded,
            evidence=list(extension.risk_flags),
        )

    def _rootkit_finding_remediation_item(self, finding: Any) -> PersistenceItem | None:
        result = self.rootkit_result
        if result is not None:
            for extension in result.extensions:
                if extension.path and any(extension.path in str(evidence) for evidence in finding.evidence):
                    return self._rootkit_extension_remediation_item(extension)
                if extension.bundle_id and any(extension.bundle_id in str(evidence) for evidence in finding.evidence):
                    return self._rootkit_extension_remediation_item(extension)
        for evidence in finding.evidence:
            text = str(evidence)
            candidate = text.split(": ", 1)[1].strip() if ": " in text else text.strip()
            candidate = candidate.split(" (", 1)[0].strip()
            if not candidate.startswith("/"):
                continue
            path = Path(candidate)
            if path.suffix.lower() not in {".plist", ".kext", ".systemextension", ".dext"}:
                continue
            mechanism = "launch_daemon" if "LaunchDaemons" in candidate else "launch_agent" if "LaunchAgents" in candidate else "kernel_extension"
            label = path.stem
            if path.suffix.lower() == ".plist" and path.is_file() and not path.is_symlink():
                try:
                    payload = plistlib.loads(path.read_bytes())
                    label = str(payload.get("Label") or label) if isinstance(payload, dict) else label
                except (OSError, plistlib.InvalidFileException, ValueError):
                    pass
            return PersistenceItem.create(mechanism, candidate, plist_path=candidate if path.suffix.lower() == ".plist" else "", label=label, evidence=list(finding.evidence))
        return None

    def export_rootkit_evidence(self) -> None:
        if self.rootkit_result is None:
            self.run_rootkit_review()
        if self.rootkit_result is None:
            return
        default = get_reports_dir() / f"rootkit_suspect_review_{self.rootkit_result.scan_id}.html"
        path, _ = QFileDialog.getSaveFileName(self, "Export Rootkit Suspect Review", str(default), "Reports (*.html *.docx *.xlsx);;JSON Evidence (*.json)")
        if not path:
            return
        output = Path(path)
        if output.suffix.lower() == ".html":
            saved = export_rootkit_report_html(self.rootkit_result, output)
        elif output.suffix.lower() in {".docx", ".xlsx"}:
            saved = export_rootkit_report_professional(self.rootkit_result, output)
        else:
            saved = export_rootkit_report_json(self.rootkit_result, output)
        manifest = export_evidence_package(self.rootkit_result, output.parent)
        QMessageBox.information(self, "Rootkit Review Exported", f"Saved report to:\n{saved}\n\nEvidence manifest:\n{manifest}")
