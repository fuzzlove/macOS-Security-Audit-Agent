from __future__ import annotations

import json
import html
from collections import Counter
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.persistence_intelligence.baseline import PersistenceBaselineManager
from mac_audit_agent.persistence_intelligence.chain_view import build_chain_view
from mac_audit_agent.persistence_intelligence.diagnostics import build_diagnostics
from mac_audit_agent.persistence_intelligence.report_adapter import export_persistence_report_html, export_persistence_report_json, export_persistence_report_markdown
from mac_audit_agent.persistence_intelligence.scanner import PersistenceIntelligenceEngine
from mac_audit_agent.persistence_intelligence.timeline import build_timeline
from mac_audit_agent.reporting import get_reports_dir
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
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.engine = PersistenceIntelligenceEngine()
        self.baselines = PersistenceBaselineManager()
        self.report = None
        self._finding_detail_payloads: list[dict[str, Any]] = []
        self._all_inventory_rows: list[dict[str, Any]] = []
        self._all_finding_rows: list[dict[str, Any]] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        header = QHBoxLayout()
        title = QLabel("Persistence Intelligence")
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)
        self.scan_button = QPushButton("Run Persistence Scan")
        self.scan_button.setToolTip("Run read-only persistence scanners and refresh inventory, findings, coverage, timeline, and diagnostics.")
        self.scan_button.clicked.connect(self.run_scan)
        header.addWidget(self.scan_button)
        self.export_button = QPushButton("Export Report")
        self.export_button.setToolTip("Export the current Persistence Intelligence report as HTML.")
        self.export_button.clicked.connect(self.export_report)
        header.addWidget(self.export_button)
        layout.addLayout(header)
        self.summary = QLabel("No persistence scan has run yet.")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet("color: #D0D7E2; font-weight: 600;")
        layout.addWidget(self.summary)
        filter_row = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search label, path, target, owner, mechanism, or evidence")
        self.severity_filter = self._filter_combo("All severities")
        self.risk_filter = self._filter_combo("All risks")
        self.mechanism_filter = self._filter_combo("All mechanisms")
        self.baseline_filter = self._filter_combo("All baseline states")
        self.signature_filter = self._filter_combo("All signatures")
        self.trust_filter = self._filter_combo("All trust labels")
        self.scanner_filter = self._filter_combo("All scanner sources")
        for widget in [
            self.search_box,
            self.severity_filter,
            self.risk_filter,
            self.mechanism_filter,
            self.baseline_filter,
            self.signature_filter,
            self.trust_filter,
            self.scanner_filter,
        ]:
            filter_row.addWidget(widget)
        layout.addLayout(filter_row)
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
        self.inventory_table = self._table(["Mechanism", "Label / Name", "Path", "Target", "Loaded", "Disabled", "RunAtLoad", "KeepAlive", "Owner", "Permissions", "Signature", "Trust", "Risk", "Baseline"])
        self.findings_table = self._table(["Severity", "Risk", "Confidence", "Mechanism", "Name / Label", "Target Path", "Owner", "Signature", "Baseline Status", "Why Flagged", "Recommended Action", "First Seen", "Status"])
        self.findings_table.currentCellChanged.connect(self._show_selected_finding_detail)
        self.chain_text = QTextEdit()
        self.chain_text.setReadOnly(True)
        self.timeline_table = self._table(["Timestamp", "Event", "Severity", "Mechanism", "Label"])
        self.coverage_table = self._table(["Scanner", "Status", "Items", "Findings", "Warnings", "Errors"])
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
        self.export_html_button = QPushButton("Export HTML")
        self.export_json_button = QPushButton("Export JSON")
        self.export_md_button = QPushButton("Export Markdown")
        for button in [self.export_html_button, self.export_json_button, self.export_md_button]:
            reports_layout.addWidget(button)
        self.export_html_button.clicked.connect(lambda: self.export_report("html"))
        self.export_json_button.clicked.connect(lambda: self.export_report("json"))
        self.export_md_button.clicked.connect(lambda: self.export_report("md"))
        dashboard_page = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_page)
        dashboard_layout.setSpacing(10)
        self.dashboard_state_label = QLabel("No persistence scan has been run yet. Run Persistence Scan to populate this section.")
        self.dashboard_state_label.setWordWrap(True)
        self.dashboard_state_label.setStyleSheet("font-weight: 700; color: #D0D7E2;")
        dashboard_layout.addWidget(self.dashboard_state_label)
        self.summary_card_grid = QGridLayout()
        self.summary_cards: dict[str, tuple[QLabel, QLabel]] = {}
        for index, title_text in enumerate(["Total Persistence Items", "High-Risk Findings", "New Since Baseline", "Suspicious Targets", "Scanner Coverage"]):
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
        dashboard_layout.addWidget(QLabel("Top Persistence Risks"))
        dashboard_layout.addWidget(self.top_risks_table)
        self.mechanism_table = self._table(["Mechanism", "Items", "Findings", "Highest Risk"])
        dashboard_layout.addWidget(QLabel("Mechanism Breakdown"))
        dashboard_layout.addWidget(self.mechanism_table)
        self.dashboard_coverage_table = self._table(["Scanner", "Status", "Items", "Findings", "Last Run", "Warning/Error"])
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
        self.tabs.addTab(self.diagnostics_text, "Diagnostics")
        self.tabs.addTab(reports_page, "Reports")
        layout.addWidget(self.tabs)
        self._set_initial_empty_state()

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
        self.dashboard_state_label.setText("No persistence scan has been run yet. Run Persistence Scan to populate this section.")
        self._fill_table(self.top_risks_table, [["", "No elevated persistence risks detected.", "", "", "", "Run Persistence Scan"]])
        self._fill_table(self.mechanism_table, [["No data", "Not scanned", "Not scanned", "Unknown"]])
        self._fill_table(self.dashboard_coverage_table, [["No scanner data", "Not scanned", "0", "0", "Not scanned", "Run Persistence Scan"]])
        self._fill_table(self.inventory_table, [["No persistence data available yet.", "", "", "", "", "", "", "", "", "", "", "Unknown", "Unknown", "Unknown"]])
        self._fill_table(self.findings_table, [["No persistence findings detected.", "", "", "", "", "", "", "", "", "", "", "", ""]])

    def run_scan(self) -> None:
        try:
            self.dashboard_state_label.setText("Running Persistence Intelligence scan...")
            self.summary.setText("Running Persistence Intelligence scan...")
            self.report = self.engine.scan()
            self._render_report()
        except Exception as exc:
            self.dashboard_state_label.setText("Persistence Intelligence failed. View Diagnostics.")
            self.summary.setText("Persistence Intelligence failed. View Diagnostics.")
            QMessageBox.warning(self, "Persistence Scan Failed", str(exc))

    def _render_report(self) -> None:
        if self.report is None:
            return
        critical_high = sum(1 for finding in self.report.findings if finding.severity in {"CRITICAL", "HIGH"})
        unsigned = sum(1 for item in self.report.items if item.signed_status == "unsigned")
        suspicious = sum(1 for item in self.report.items if any("command invokes" in evidence for evidence in item.evidence))
        writable = sum(1 for item in self.report.items if item.world_writable)
        techniques = sorted({tech for item in self.report.items for tech in item.mitre_techniques})
        self.summary.setText(
            f"Items: {len(self.report.items)} | Findings: {len(self.report.findings)} | Critical/High: {critical_high} | "
            f"Unsigned: {unsigned} | Suspicious commands: {suspicious} | World-writable references: {writable} | "
            f"MITRE techniques: {', '.join(techniques) or 'none'} | Posture score: {self.report.posture_score} | Last scan: {self.report.completed_at}"
        )
        self._render_dashboard()
        self._all_inventory_rows = [self._inventory_row(item) for item in self.report.items]
        self._all_finding_rows = [self._finding_row(finding) for finding in self.report.findings]
        self._populate_filters()
        self._apply_filters()
        self._fill_table(self.timeline_table, [[event["timestamp"], event["event"], event["severity"], event["mechanism"], event["label"]] for event in build_timeline(self.report.items)])
        self._fill_table(self.coverage_table, [[c["scanner_id"], c["coverage_status"], c["item_count"], c["finding_count"], c["warning_count"], c["error_count"]] for c in self.report.coverage])
        self.chain_text.setHtml(self._chain_view_html())
        self.diagnostics_text.setPlainText(json.dumps(build_diagnostics(self.report), indent=2, sort_keys=True))
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
        self.dashboard_state_label.setText("No persistence findings detected." if not self.report.findings else "Persistence Intelligence scan completed. Review top risks first.")
        card_values = {
            "Total Persistence Items": (str(len(self.report.items)), f"Last scan: {_display(self.report.completed_at)}"),
            "High-Risk Findings": (f"{critical} critical / {high} high", "Critical and high persistence findings requiring first review."),
            "New Since Baseline": (f"{added} added / {changed} changed", "Baseline comparison signals for persistence drift."),
            "Suspicious Targets": (f"{unsigned} unsigned / {temp_targets} temp / {missing_targets} missing", "Unsigned, temporary/shared, or missing targets."),
            "Scanner Coverage": ("Degraded" if scanner_errors else "Healthy", f"{len(scanner_errors)} scanner(s) need review." if scanner_errors else "All scanner coverage rows reported healthy or clean."),
        }
        for title, (value, detail) in card_values.items():
            value_label, detail_label = self.summary_cards[title]
            value_label.setText(value or "Not scanned")
            detail_label.setText(detail or "No additional detail.")
        self._fill_table(self.top_risks_table, self._top_risk_rows())
        self._fill_table(self.mechanism_table, self._mechanism_rows())
        self._fill_table(self.dashboard_coverage_table, self._coverage_rows())

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
            rows.append([index, finding.severity, _short(item.label or item.name if item else finding.title, limit=52), item.mechanism if item else "Unknown", _short("; ".join(finding.evidence[:2]) or finding.description, limit=90), _short(finding.suggested_fix, limit=90)])
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
        return [[c.get("scanner_id", "Unknown"), c.get("coverage_status", "Unknown"), c.get("item_count", 0), c.get("finding_count", 0), self.report.completed_at, "; ".join(str(c.get(key, 0)) for key in ["warning_count", "error_count"])] for c in self.report.coverage]

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
            [[row["mechanism"], row["label"], row["path"], row["target"], row["loaded"], row["disabled"], row["run_at_load"], row["keep_alive"], row["owner"], row["permissions"], row["signature"], row["trust"], row["risk"], row["baseline"]] for row in rows],
        )

    def _fill_findings(self, rows: list[dict[str, Any]]) -> None:
        self._finding_detail_payloads = rows
        if not rows:
            self._fill_table(self.findings_table, [["No persistence findings detected.", "", "", "", "", "", "", "", "", "", "", "", ""]])
            self.finding_detail.setPlainText("No persistence findings detected.")
            return
        self._fill_table(
            self.findings_table,
            [[row["severity"], row["risk"], row["confidence"], row["mechanism"], row["label"], row["target"], row["owner"], row["signature"], row["baseline"], _short(row["why"], limit=95), _short(row["action"], limit=95), row["first_seen"], row["status"]] for row in rows],
        )
        for row_index in range(len(rows)):
            first_item = self.findings_table.item(row_index, 0)
            if first_item is not None:
                first_item.setData(Qt.UserRole + 1, row_index)

    def _chain_view_html(self) -> str:
        if self.report is None:
            return ""
        sections = []
        chains = build_chain_view(self.report.items, self.report.findings)
        item_by_id = {item.item_id: item for item in self.report.items}
        for chain in chains:
            item = item_by_id.get(str(chain.get("item_id", "")))
            risk = risk_badge_html(item.risk_level, item.risk_score) if item is not None else risk_badge_html("unknown")
            trust = risk_badge_html(item.trust_label, item.trust_score) if item is not None else risk_badge_html("unknown")
            relationships = "".join(
                f"<li><strong>{html.escape(str(rel.get('type', '')).replace('_', ' ').title())}:</strong> {html.escape(str(rel.get('value', '')))}</li>"
                for rel in chain.get("relationships", [])
                if isinstance(rel, dict)
            )
            sections.append(
                f"<section><h3>{risk} {trust} {html.escape(str(chain.get('item_id', '')))}</h3><ul>{relationships}</ul></section>"
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
            f"MITRE / NIST: {_display(finding.mitre_mapping)} | {_display(finding.nist_mapping)}",
        ]
        self.finding_detail.setPlainText("\n".join(details))

    def create_baseline(self) -> None:
        if self.report is None:
            self.run_scan()
        if self.report is None:
            return
        path = self.baselines.create_baseline(self.baseline_name.text().strip() or "trusted", self.report.items)
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
        suffix = "md" if fmt == "md" else fmt
        default = get_reports_dir() / f"persistence_intelligence_{self.report.scan_id}.{suffix}"
        path, _ = QFileDialog.getSaveFileName(self, "Export Persistence Intelligence Report", str(default), "All Files (*)")
        if not path:
            return
        output = Path(path)
        if fmt == "json":
            saved = export_persistence_report_json(self.report, output)
        elif fmt == "md":
            saved = export_persistence_report_markdown(self.report, output)
        else:
            saved = export_persistence_report_html(self.report, output)
        QMessageBox.information(self, "Persistence Report Exported", f"Saved report to:\n{saved}")
