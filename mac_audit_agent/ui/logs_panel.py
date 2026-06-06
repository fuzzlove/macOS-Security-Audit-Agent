from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
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


class LogsPanel(QFrame):
    refresh_requested = Signal()
    open_reports_requested = Signal()
    clear_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("logsPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._build_ui()
        self.set_logs({"events": [], "scan_logs": [], "summary": "No logs loaded yet."})

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Logs")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        subtitle = QLabel("Local event history, notification decisions, and scan output.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        toolbar = QHBoxLayout()
        self.category_combo = QComboBox()
        self.category_combo.addItem("All Log Categories", "all")
        self.category_combo.addItem("Monitor Events", "monitor_events")
        self.category_combo.addItem("Scan Command Logs", "scan_command_logs")
        self.category_combo.addItem("Remediation Actions", "remediation_actions")
        self.category_combo.addItem("Application File Logs", "app_file_logs")
        self.refresh_button = QPushButton("Refresh")
        self.clear_category_button = QPushButton("Clear Category")
        self.open_reports_button = QPushButton("Open Reports Folder")
        self.category_combo.setToolTip("Choose which local log category to show and clear.")
        toolbar.addWidget(self.category_combo)
        for button in [self.refresh_button, self.clear_category_button, self.open_reports_button]:
            button.setMinimumHeight(36)
            button.setToolTip(button.text())
            button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
            toolbar.addWidget(button)
        layout.addLayout(toolbar)

        self.summary_label = QLabel("No logs loaded yet.")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.table = _make_table(["Timestamp", "Type", "Severity", "Decision", "Reason", "Evidence"])
        layout.addWidget(self.table, 1)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a log row to inspect it in detail.")
        layout.addWidget(self.details)

        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.clear_category_button.clicked.connect(self._emit_clear_requested)
        self.open_reports_button.clicked.connect(self.open_reports_requested.emit)
        self.category_combo.currentIndexChanged.connect(self._apply_filter)
        self.table.itemSelectionChanged.connect(self._refresh_details)
        self._rows: list[dict[str, Any]] = []

    def set_logs(self, payload: dict[str, Any]) -> None:
        events = list(payload.get("events", []))
        scan_logs = list(payload.get("scan_logs", []))
        command_logs = list(payload.get("command_logs", []))
        remediation_actions = list(payload.get("remediation_actions", []))
        app_file_logs = list(payload.get("app_file_logs", []))
        rows = []
        rows.extend(self._tag_rows(events, "monitor_events"))
        rows.extend(self._tag_rows(scan_logs, "scan_command_logs"))
        rows.extend(self._tag_rows(command_logs, "scan_command_logs"))
        rows.extend(self._tag_rows(remediation_actions, "remediation_actions"))
        rows.extend(self._tag_rows(app_file_logs, "app_file_logs"))
        self._rows = rows
        self.summary_label.setText(str(payload.get("summary", "No logs loaded yet.")))
        self._apply_filter()

    def _tag_rows(self, rows: list[Any], category: str) -> list[dict[str, Any]]:
        tagged: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            item = dict(row)
            item.setdefault("log_category", category)
            tagged.append(item)
        return tagged

    def _apply_filter(self) -> None:
        selected_category = str(self.category_combo.currentData() or "all")
        rows = [row for row in self._rows if selected_category == "all" or row.get("log_category") == selected_category]
        self.table.setRowCount(0)
        for row_data in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                str(row_data.get("timestamp", row_data.get("executed_at", row_data.get("created_at", "")))),
                str(row_data.get("event_type", row_data.get("collector_name", row_data.get("action_type", row_data.get("log_category", ""))))),
                str(row_data.get("severity", "")),
                str(row_data.get("notification_decision", row_data.get("exit_code", row_data.get("result_text", "")))),
                str(row_data.get("notification_reason", row_data.get("error", row_data.get("stderr", row_data.get("explanation", ""))))),
                self._evidence_text(row_data),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, row_data)
                self.table.setItem(row, column, item)
        self.table.resizeRowsToContents()
        self._refresh_details()

    def _emit_clear_requested(self) -> None:
        self.clear_requested.emit(str(self.category_combo.currentData() or "all"))

    def _evidence_text(self, row_data: dict[str, Any]) -> str:
        evidence = str(row_data.get("evidence", row_data.get("command_or_source", row_data.get("command_text", row_data.get("stdout", row_data.get("message", ""))))))
        count = int(row_data.get("occurrence_count", 1) or 1)
        if count > 1:
            category = str(row_data.get("duplicate_category", "duplicate_burst") or "duplicate_burst").replace("_", " ")
            return f"{evidence} | repeated {count} times ({category})"
        return evidence

    def _refresh_details(self) -> None:
        selected = self.table.currentItem()
        if selected is None:
            self.details.setPlainText("No log row selected.")
            return
        row = selected.row()
        item = self.table.item(row, 0)
        if item is None:
            return
        data = item.data(Qt.UserRole)
        if not isinstance(data, dict):
            self.details.setPlainText("No log details available.")
            return
        lines = [f"{key}: {value}" for key, value in data.items()]
        self.details.setPlainText("\n".join(lines))
