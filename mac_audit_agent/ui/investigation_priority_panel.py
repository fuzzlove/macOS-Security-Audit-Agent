from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


PRIORITY_TABLE_HEADERS = [
    "Rank",
    "Title",
    "Score",
    "Severity",
    "Confidence",
    "Why ranked here",
    "Next action",
    "Effort",
]


def _make_table() -> QTableWidget:
    table = QTableWidget(0, len(PRIORITY_TABLE_HEADERS))
    table.setHorizontalHeaderLabels(PRIORITY_TABLE_HEADERS)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    table.setSizePolicy(table.sizePolicy().horizontalPolicy(), table.sizePolicy().verticalPolicy())
    return table


class InvestigationPriorityPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("investigationPriorityPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self._report: dict[str, Any] = {}
        self._table_rows: dict[QTableWidget, list[dict[str, Any]]] = {}
        self._build_ui()
        self.set_report(
            {
                "generated_at": "",
                "scan_id": "",
                "summary": "No findings are ranked yet.",
                "top_3": [],
                "top_10": [],
                "full_queue": [],
                "counts": {"top_3": 0, "top_10": 0, "full_queue": 0},
            }
        )

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.title_label = QLabel("Investigation Priorities")
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        self.subtitle_label = QLabel("Ranked by persistence, admin changes, network changes, unknown devices, trust decay, and suppression history.")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)

        summary_row = QVBoxLayout()
        self.generated_label = QLabel("Generated: not yet")
        self.scan_label = QLabel("Scan: none")
        self.summary_label = QLabel("No findings to prioritize.")
        for label in [self.generated_label, self.scan_label, self.summary_label]:
            label.setWordWrap(True)
            label.setStyleSheet("color: #D6E4FF;")
            summary_row.addWidget(label)
        layout.addLayout(summary_row)

        self.tabs = QTabWidget()
        self.top_3_table = _make_table()
        self.top_10_table = _make_table()
        self.full_queue_table = _make_table()
        self._add_tab(self.top_3_table, "Top 3")
        self._add_tab(self.top_10_table, "Top 10")
        self._add_tab(self.full_queue_table, "Full Queue")
        self.tabs.currentChanged.connect(self._refresh_details_from_selection)
        layout.addWidget(self.tabs)

        self.details_view = QTextEdit()
        self.details_view.setReadOnly(True)
        self.details_view.setPlaceholderText("Select a priority item to see the full explanation.")
        self.details_view.setMinimumHeight(220)
        layout.addWidget(QLabel("Selected Priority Details"))
        layout.addWidget(self.details_view)

    def _add_tab(self, table: QTableWidget, title: str) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(table)
        table.itemSelectionChanged.connect(self._refresh_details_from_selection)
        self.tabs.addTab(page, title)

    def set_report(self, report: dict[str, Any]) -> None:
        self._report = report or {}
        self.generated_label.setText(f"Generated: {self._report.get('generated_at', 'not yet') or 'not yet'}")
        self.scan_label.setText(f"Scan: {self._report.get('scan_id', 'none') or 'none'}")
        summary = str(self._report.get("summary", "No findings to prioritize."))
        counts = self._report.get("counts", {}) if isinstance(self._report.get("counts", {}), dict) else {}
        self.summary_label.setText(
            f"{summary} Top 3: {counts.get('top_3', 0)} | Top 10: {counts.get('top_10', 0)} | Full queue: {counts.get('full_queue', 0)}"
        )
        self._set_table_rows(self.top_3_table, list(self._report.get("top_3", [])))
        self._set_table_rows(self.top_10_table, list(self._report.get("top_10", [])))
        self._set_table_rows(self.full_queue_table, list(self._report.get("full_queue", [])))
        current = self.current_table()
        if current is not None and current.rowCount() > 0 and current.currentRow() < 0:
            current.selectRow(0)
        self._refresh_details_from_selection()

    def _set_table_rows(self, table: QTableWidget, rows: list[dict[str, Any]]) -> None:
        self._table_rows[table] = rows
        table.setRowCount(0)
        if not rows:
            return
        for row_index, row in enumerate(rows):
            table.insertRow(row_index)
            values = [
                str(row_index + 1),
                str(row.get("title", "")),
                str(row.get("rank_score", row.get("priority_score", ""))),
                str(row.get("severity", "")),
                str(row.get("confidence", "")),
                str(row.get("why_ranked_here", "")),
                str(row.get("recommended_next_action", "")),
                str(row.get("estimated_investigation_effort", "")),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, row)
                table.setItem(row_index, column, item)
        table.resizeRowsToContents()

    def _refresh_details_from_selection(self) -> None:
        table = self.current_table()
        if table is None:
            self.details_view.setPlainText("No findings to prioritize. Run a scan to populate investigation priorities.")
            return
        row = table.currentRow()
        rows = self._table_rows.get(table, [])
        if row < 0 or row >= len(rows):
            if rows:
                row = 0
                table.selectRow(0)
            else:
                self.details_view.setPlainText("No findings to prioritize. Run a scan to populate investigation priorities.")
                return
        item = rows[row]
        details = [
            f"Title: {item.get('title', '')}",
            f"Rank score: {item.get('rank_score', item.get('priority_score', ''))}",
            f"Severity: {item.get('severity', '')}",
            f"Confidence: {item.get('confidence', '')}",
            f"Why ranked here: {item.get('why_ranked_here', '')}",
            f"Evidence:\n{item.get('evidence', '')}",
            f"Recommended next action: {item.get('recommended_next_action', '')}",
            f"Estimated investigation effort: {item.get('estimated_investigation_effort', '')}",
            f"Trust score impact: {item.get('trust_score_impact', 0)}",
            f"Persistence involvement: {'yes' if item.get('persistence_involvement') else 'no'}",
            f"Network involvement: {'yes' if item.get('network_involvement') else 'no'}",
            f"Admin involvement: {'yes' if item.get('admin_involvement') else 'no'}",
            f"User presence correlation: {'yes' if item.get('user_presence_correlation') else 'no'}",
            f"Suppression history count: {item.get('suppression_history_count', 0)}",
            f"Review state: {item.get('review_state', '')}",
            f"First seen: {item.get('first_seen', '')}",
            f"Source trace: {item.get('source_trace', '')}",
        ]
        self.details_view.setPlainText("\n".join(details))

    def current_table(self) -> QTableWidget | None:
        index = self.tabs.currentIndex()
        widget = self.tabs.widget(index)
        if widget is None:
            return None
        table = widget.findChild(QTableWidget)
        return table
