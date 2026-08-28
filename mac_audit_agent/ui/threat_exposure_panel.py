from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHBoxLayout, QVBoxLayout, QWidget


class ThreatExposureManagementPanel(QWidget):
    action_requested = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.summary = QLabel("Threat Exposure Management: no assessment attached")
        self.summary.setAccessibleName("Threat exposure summary")
        self.summary.setWordWrap(True); layout.addWidget(self.summary)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(("Priority", "Component", "Category", "CVE", "KEV/Exploit Status", "Score", "Evidence", "Recommendation"))
        self.table.setAccessibleName("Prioritized threat exposures"); self.table.horizontalHeader().setStretchLastSection(True); layout.addWidget(self.table)
        controls = QHBoxLayout()
        for label, action in (("Investigate", "investigate"), ("View Evidence", "view_evidence"), ("Prioritize Remediation", "prioritize_remediation"), ("Export Report", "export_report"), ("Create Ticket", "create_ticket")):
            button = QPushButton(label); button.clicked.connect(lambda _checked=False, value=action: self.action_requested.emit(value, self._selected_exposure_id())); controls.addWidget(button)
        controls.addStretch(1); layout.addLayout(controls)
        self.notice = QLabel("Decision support only. Exposure priority does not prove exploitation or compromise, and actions require authorized workflows.")
        self.notice.setWordWrap(True); layout.addWidget(self.notice)

    def set_assessment(self, payload: dict) -> None:
        assessment = payload.get("assessment", payload) if isinstance(payload, dict) else {}
        exposures = [item for item in assessment.get("exposures", []) if isinstance(item, dict)]
        self.summary.setText(f"Overall Exposure Score: {assessment.get('overall_exposure_score', 'not collected')}/100 · Critical: {sum(item.get('severity') == 'critical' for item in exposures)} · KEV: {sum(item.get('exploit_status') == 'known_exploited_in_wild' for item in exposures)} · Updated: {assessment.get('timestamp', 'not collected')}")
        self.table.setRowCount(len(exposures))
        for row, item in enumerate(exposures):
            values = (row + 1, item.get("affected_component", ""), item.get("risk_category", ""), item.get("cve_id", ""), item.get("exploit_status", ""), item.get("exposure_score", ""), ", ".join(str(value) for value in item.get("evidence_reference", [])), item.get("recommendation", ""))
            for column, value in enumerate(values): self.table.setItem(row, column, QTableWidgetItem(str(value)))
            self.table.item(row, 0).setData(256, str(item.get("exposure_id", "")))
        self.table.resizeColumnsToContents()

    def _selected_exposure_id(self) -> str:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return str(item.data(256) or "") if item else ""
