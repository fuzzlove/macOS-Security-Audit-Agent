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

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.audit_button = QPushButton("Audit System Monitor Deployment")
        self.verify_button = QPushButton("Verify Event Flow")
        for button in [self.refresh_button, self.audit_button, self.verify_button]:
            button.setMinimumHeight(36)
            button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
            button.setToolTip(button.text())
            toolbar.addWidget(button)
        layout.addLayout(toolbar)

        self.table = _make_table(["Component", "Status", "Summary", "Evidence", "Next Step"])
        layout.addWidget(self.table, 1)

        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.audit_button.clicked.connect(self.audit_deployment_requested.emit)
        self.verify_button.clicked.connect(self.verify_event_flow_requested.emit)

    def set_report(self, payload: dict[str, Any]) -> None:
        checks = list(payload.get("checks", []))
        self.summary_label.setText(
            f"Overall status: {payload.get('overall_status', 'unknown')} | Health score: {payload.get('health_score', 0)}/100 | Checks: {len(checks)}"
        )
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
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.resizeRowsToContents()
