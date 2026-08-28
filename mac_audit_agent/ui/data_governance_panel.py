from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class DataGovernancePanel(QWidget):
    action_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.summary = QLabel("Data Governance: no policy inventory attached")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(("Data Type", "Classification", "Purpose", "Retention", "Minimum Role"))
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.status = QLabel("Access History: not loaded · Sharing: disabled unless explicitly authorized")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QHBoxLayout()
        for label, action in (("Review Data", "review_data"), ("Modify Retention", "modify_retention"), ("Export Audit", "export_audit"), ("Review Permissions", "review_permissions")):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, selected=action: self.action_requested.emit(selected))
            buttons.addWidget(button)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Retention, export, sharing, and external AI actions require policy validation and explicit authorization."))

    def set_governance(self, payload):
        report = payload.get("transparency_report", payload) if isinstance(payload, dict) else {}
        rows = report.get("data_types", []) if isinstance(report, dict) else []
        self.summary.setText(f"Data Governance: {len(rows)} classified data types · Unknown types fail closed")
        self.table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            retention = "Organization-defined" if item.get("retention_days") is None else f"{item.get('retention_days')} days"
            values = (item.get("data_type", ""), item.get("classification", ""), item.get("purpose", ""), retention, item.get("minimum_role", ""))
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(str(value)))
        chain = payload.get("audit_chain_verified", "not checked") if isinstance(payload, dict) else "not checked"
        self.status.setText(f"Access Audit Chain: {chain} · External sharing: disabled by default for operational data")


__all__ = ["DataGovernancePanel"]
