from __future__ import annotations

import json
from uuid import uuid4

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.keylogger_detection import KeyloggerFinding, KeyloggerScanner
from mac_audit_agent.keylogger_reporting import REPORT_FORMATS, export_keylogger_report
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.remediation.keylogger_remediation import KeyloggerRemediationEngine


class KeyloggerDetectionPanel(QWidget):
    def __init__(self, parent=None, *, db=None, scanner: KeyloggerScanner | None = None) -> None:
        super().__init__(parent)
        self.db = db
        self.scanner = scanner or KeyloggerScanner()
        self.remediation = KeyloggerRemediationEngine()
        self.report = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        explanation = QLabel(
            "Read-only detection of enabled keyboard event taps and applications with Input Monitoring or Accessibility access. "
            "A permission is exposure, not proof of infection; MSAA raises confidence when behavioral and trust signals correlate."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        actions = QHBoxLayout()
        actions.addStretch(1)
        self.scan_button = QPushButton("Scan for Keylogger Indicators")
        self.scan_button.setToolTip("Enumerate keyboard event taps, review relevant privacy permissions, and verify process signatures without collecting keystrokes.")
        self.scan_button.clicked.connect(self.run_scan)
        actions.addWidget(self.scan_button)
        self.export_format = QComboBox()
        self.export_format.setAccessibleName("Keylogger report export format")
        self.export_format.setToolTip("Static, non-executable handoff formats are listed first. Office files are macro-free and contain no formulas.")
        for format_id, label, _file_filter in REPORT_FORMATS:
            self.export_format.addItem(label, format_id)
        self.export_format.setEnabled(False)
        actions.addWidget(self.export_format)
        self.export_button = QPushButton("Export Professional Report")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_report)
        actions.addWidget(self.export_button)
        layout.addLayout(actions)

        self.summary = QLabel("No keylogger detection scan has run yet.")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["Severity", "Threat", "Confidence", "False-positive risk", "Process / Client", "PID", "Detection", "Classification", "Action"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideRight)
        header = self.table.horizontalHeader()
        for column in (0, 1, 2, 3, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        for column in (4, 6, 7):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
        header.setSectionResizeMode(8, QHeaderView.Stretch)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.currentCellChanged.connect(self._show_detail)
        layout.addWidget(self.table, 1)
        self.details = QTextBrowser()
        self.details.setAccessibleName("Selected Keylogger Detection Finding Details")
        self.details.setPlaceholderText("Select a finding to review evidence and recommended action.")
        layout.addWidget(self.details, 1)
        remediation_actions = QGridLayout()
        remediation_actions.setHorizontalSpacing(8)
        remediation_actions.setVerticalSpacing(8)
        self.investigate_button = QPushButton("Investigate")
        self.suspend_button = QPushButton("Suspend Process")
        self.stop_button = QPushButton("Stop Process")
        self.unhook_button = QPushButton("Unhook & Quarantine")
        self.unhook_button.setObjectName("unhookKeyloggerButton")
        self.unhook_button.setAccessibleName("Unhook and quarantine selected keylogger indicator")
        self.unhook_button.setToolTip(
            "Preserve evidence, verify the event-tap owner, terminate it to release the keyboard hook, "
            "and move its exact executable and persistence entries into reversible quarantine."
        )
        self.quarantine_button = QPushButton("Quarantine")
        self.remove_button = QPushButton("Remove Threat")
        self.verify_button = QPushButton("Verify Remediation")
        remediation_buttons = (self.investigate_button, self.suspend_button, self.stop_button, self.unhook_button, self.quarantine_button, self.remove_button, self.verify_button)
        for button in remediation_buttons:
            button.setEnabled(False)
        remediation_actions.addWidget(QLabel("Intervention"), 0, 0, 1, 2)
        for column, button in enumerate((self.investigate_button, self.suspend_button, self.stop_button)):
            remediation_actions.addWidget(button, 1 + column // 2, column % 2)
        remediation_actions.addWidget(QLabel("Removal (evidence first; reversible quarantine)"), 3, 0, 1, 2)
        for column, button in enumerate((self.unhook_button, self.quarantine_button, self.remove_button)):
            remediation_actions.addWidget(button, 4 + column // 2, column % 2)
        remediation_actions.addWidget(QLabel("Remediation and verification"), 6, 0, 1, 2)
        remediation_actions.addWidget(self.verify_button, 7, 0)
        for column in range(2):
            remediation_actions.setColumnStretch(column, 1)
        self.investigate_button.clicked.connect(self.investigate_selected)
        self.suspend_button.clicked.connect(lambda: self.contain_selected(suspend=True))
        self.stop_button.clicked.connect(lambda: self.contain_selected(suspend=False))
        self.unhook_button.clicked.connect(self.unhook_selected)
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        self.remove_button.clicked.connect(self.remove_selected)
        self.verify_button.clicked.connect(self.verify_selected)
        layout.addLayout(remediation_actions)

    def run_scan(self) -> None:
        self.scan_button.setEnabled(False)
        self.summary.setText("Scanning keyboard event taps and privacy permissions…")
        try:
            self.report = self.scanner.scan()
            self._render()
            self._record_elevated_events()
            self.export_format.setEnabled(True)
            self.export_button.setEnabled(True)
        except Exception as exc:
            self.summary.setText("Keylogger detection scan failed. No infection determination was made.")
            QMessageBox.warning(self, "Keylogger Scan Failed", str(exc))
        finally:
            self.scan_button.setEnabled(True)

    def _render(self) -> None:
        report = self.report
        if report is None:
            return
        elevated = sum(1 for item in report.findings if item.severity in {"high", "critical"})
        coverage = ", ".join(f"{name}: {status}" for name, status in report.coverage.items())
        self.summary.setText(
            f"Keyboard taps: {report.event_tap_count} | Relevant privacy grants: {report.tcc_grant_count} | "
            f"Findings: {len(report.findings)} | High/Critical: {elevated} | "
            f"Measured accuracy: {'not measured' if report.accuracy_rate_percent is None else f'{report.accuracy_rate_percent:.1f}%'} | Coverage: {coverage}"
        )
        self.table.setRowCount(len(report.findings))
        for row, finding in enumerate(report.findings):
            values = [
                finding.severity.upper(), f"{finding.score}%", f"{finding.analytic_confidence_percent}%",
                f"{finding.false_positive_risk_percent}%", finding.process_name or finding.bundle_id,
                finding.pid or "", finding.title, finding.classification, finding.recommendation,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, finding.to_dict())
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.details.setPlainText("No suspicious keyboard event tap was found." if not report.findings else "Select a finding to review its evidence.")

    def _show_detail(self, row: int, _column: int, _previous_row: int, _previous_column: int) -> None:
        item = self.table.item(row, 0)
        if item is None:
            return
        payload = item.data(Qt.UserRole) or {}
        assessment = self.remediation.assess(payload)
        self.details.setPlainText(
            f"{payload.get('title', '')}\n\nAnalytic percentages\n"
            + f"Threat score: {payload.get('score', 0)}%\n"
            + f"Analytic confidence: {payload.get('analytic_confidence_percent', 0)}%\n"
            + f"Estimated false-positive risk: {payload.get('false_positive_risk_percent', 100)}%\n"
            + "Measured accuracy: not measured (requires adjudicated outcomes)\n"
            + f"Basis: {payload.get('percentage_basis', '')}\n\nSignals\n- "
            + "\n- ".join(payload.get("signals", []))
            + f"\n\nPath\n{payload.get('path') or 'Not resolved'}"
            + f"\n\nRecommended action\n{payload.get('recommendation', '')}"
            + "\n\nIntervention\n- " + "\n- ".join(payload.get("intervention_actions", []))
            + "\n\nRemoval\n- " + "\n- ".join(payload.get("removal_actions", []))
            + "\n\nRemediation\n- " + "\n- ".join(payload.get("remediation_actions", []))
            + "\n\nMITRE ATT&CK mapping\n"
            + json.dumps(payload.get("attack_techniques", []), indent=2, sort_keys=True)
            + "\n\nDocumented threat context (not attribution)\n"
            + json.dumps(payload.get("documented_threat_context", []), indent=2, sort_keys=True)
            + "\n\nEvidence\n"
            + json.dumps(payload.get("evidence", {}), indent=2, sort_keys=True)
            + "\n\nRemediation assessment\n"
            + json.dumps(assessment.to_dict(), indent=2, sort_keys=True)
        )
        self.investigate_button.setEnabled(True)
        actionable = bool(payload.get("path")) and not assessment.protected
        intervention_ready = assessment.threat_score >= 65 and assessment.false_positive_risk_percent <= 35
        removal_ready = assessment.threat_score >= 85 and assessment.false_positive_risk_percent <= 20
        self.suspend_button.setEnabled(actionable and bool(payload.get("pid")) and intervention_ready)
        self.stop_button.setEnabled(actionable and bool(payload.get("pid")) and intervention_ready)
        self.unhook_button.setEnabled(actionable and bool(payload.get("pid")) and intervention_ready)
        self.quarantine_button.setEnabled(actionable and intervention_ready)
        self.remove_button.setEnabled(actionable and removal_ready)
        self.verify_button.setEnabled(True)

    def _record_elevated_events(self) -> None:
        if self.db is None or self.report is None:
            return
        for finding in self.report.findings:
            if finding.severity not in {"high", "critical"}:
                continue
            timestamp = utc_now_iso()
            event = BackgroundMonitorEvent(
                event_id=f"keylogger-{uuid4().hex}",
                timestamp=timestamp,
                event_type="possible_keylogger_detected",
                severity=finding.severity,
                source="keylogger_detection_scan",
                process_name=finding.process_name,
                pid=finding.pid,
                evidence="; ".join(finding.signals),
                confidence=finding.confidence,
                recommendation=finding.recommendation,
                metadata_json=json.dumps(finding.to_dict(), sort_keys=True),
                related_process=finding.process_name,
                related_pid=finding.pid,
                related_path=finding.path,
                first_seen=timestamp,
                last_seen=timestamp,
                current_state="suspicious keyboard observation capability",
            )
            self.db.record_background_monitor_event(event, dedupe_window_seconds=600)

    def export_report(self) -> None:
        if self.report is None:
            return
        format_id = str(self.export_format.currentData() or "txt")
        selected = next(item for item in REPORT_FORMATS if item[0] == format_id)
        path, _selected = QFileDialog.getSaveFileName(self, "Export Keylogger Detection Professional Report", f"keylogger-detection.{format_id}", selected[2])
        if not path:
            return
        try:
            exported = export_keylogger_report(self.report, path, format_id)
            QMessageBox.information(self, "Keylogger Report Exported", f"Professional {format_id.upper()} report saved to:\n{exported}")
        except Exception as exc:
            QMessageBox.warning(self, "Keylogger Report Export Failed", str(exc))

    def _selected_finding(self) -> dict:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return dict(item.data(Qt.UserRole) or {}) if item else {}

    def investigate_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        try:
            result = self.remediation.investigate(finding)
            self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True, default=str))
            QMessageBox.information(self, "Evidence Preserved", f"Investigation evidence was saved to:\n{result['evidence_path']}")
        except Exception as exc:
            QMessageBox.warning(self, "Investigation Failed", str(exc))

    def contain_selected(self, *, suspend: bool) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        action = "suspend" if suspend else "terminate"
        if QMessageBox.warning(
            self, f"{action.title()} Suspected Process",
            f"MSAA will preserve evidence, revalidate PID {finding.get('pid')} and executable identity, then {action} the process.\n\n"
            "Legitimate accessibility and automation software can monitor keyboard events. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self.remediation.contain_process(finding, suspend=suspend)
            QMessageBox.information(self, "Containment Requested", json.dumps(result, indent=2, default=str))
        except Exception as exc:
            QMessageBox.warning(self, "Containment Refused", str(exc))

    def quarantine_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        assessment = self.remediation.assess(finding)
        warning = (
            f"Quarantine {finding.get('process_name') or finding.get('path')}?\n\nThreat score: {assessment.threat_score}/100\n"
            f"Target: {assessment.target_path}\n\nEvidence will be captured first. The item will be moved to restricted, non-executable quarantine and can be restored. "
            "Privacy permissions must still be reviewed in System Settings."
        )
        if QMessageBox.warning(self, "Quarantine Suspected Keylogger", warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self.remediation.quarantine(finding)
            self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True, default=str))
            QMessageBox.information(self, "Threat Quarantined", "The selected item was moved to reversible quarantine after evidence capture.")
        except Exception as exc:
            QMessageBox.warning(self, "Quarantine Refused", str(exc))

    def unhook_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        assessment = self.remediation.assess(finding)
        warning = (
            "Unhook and quarantine this suspected keyboard monitor?\n\n"
            f"Application: {finding.get('process_name') or 'Unknown'}\n"
            f"PID: {assessment.pid or 'Not running'}\n"
            f"Target: {assessment.target_path}\n"
            f"Threat score: {assessment.threat_score}/100\n"
            f"Persistence entries: {len(assessment.persistence)}\n\n"
            "MSAA will preserve evidence, revalidate the process identity, quarantine exact persistence entries, "
            "terminate the owner to release its keyboard event tap, and quarantine the executable. Nothing is "
            "permanently deleted, and macOS privacy databases are never edited. Continue?"
        )
        if QMessageBox.critical(
            self,
            "Unhook and Quarantine Keyboard Monitor",
            warning,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self.remediation.unhook_and_quarantine(finding)
            self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True, default=str))
            QMessageBox.information(
                self,
                "Keyboard Hook Released",
                "The verified event-tap owner was stopped and its exact artifacts were moved to reversible quarantine. "
                "Run a new scan after reviewing the listed privacy permissions.",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Unhook Refused", str(exc))

    def remove_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        assessment = self.remediation.assess(finding)
        warning = (
            "WARNING: MSAA is preparing a high-impact keylogger removal workflow.\n\n"
            f"Application: {finding.get('process_name')}\nTarget: {assessment.target_path}\n"
            f"Threat score: {assessment.threat_score}/100\nPersistence entries: {len(assessment.persistence)}\n\n"
            "Evidence will be captured. Exact persistence references and the primary item will be quarantined, not permanently deleted. "
            "System-wide targets require administrator authorization. Continue?"
        )
        if QMessageBox.critical(self, "Remove Confirmed Keylogger Threat", warning, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self.remediation.remove_threat(finding)
            self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True, default=str))
            QMessageBox.information(self, "Threat Removal Completed", "Confirmed components were moved to quarantine. Review the remaining TCC permission guidance and run verification.")
        except Exception as exc:
            QMessageBox.warning(self, "Removal Refused", str(exc))

    def verify_selected(self) -> None:
        finding = self._selected_finding()
        if not finding:
            return
        try:
            result = self.remediation.verify(finding)
            self.details.setPlainText(json.dumps(result, indent=2, sort_keys=True, default=str))
        except Exception as exc:
            QMessageBox.warning(self, "Verification Failed", str(exc))
