from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.intrusion_correlation import IntrusionCorrelationReport
from mac_audit_agent.ui.action_state import ActionState, apply_action_state


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


class IntrusionDetectionPanel(QFrame):
    refresh_requested = Signal()
    show_context_requested = Signal(object)
    snapshot_requested = Signal()
    export_ai_summary_requested = Signal()
    open_logs_requested = Signal()

    def __init__(self, title: str = "Intrusion Detection", subtitle: str = "Correlation, explainability, coverage, and evidence preservation.", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("intrusionDetectionPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._report: IntrusionCorrelationReport | dict[str, Any] | None = None
        self._build_ui(title, subtitle)
        self.set_report({})

    def _build_ui(self, title: str, subtitle: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        title_block = QVBoxLayout()
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet("color: #9DB0C9;")
        title_block.addWidget(self.title_label)
        title_block.addWidget(self.subtitle_label)
        header_row.addLayout(title_block)
        header_row.addStretch(1)
        self.coverage_label = QLabel("Monitoring Coverage: --")
        self.presence_label = QLabel("User presence: unknown")
        for label in [self.coverage_label, self.presence_label]:
            label.setWordWrap(True)
            label.setStyleSheet("color: #D6E4FF; font-weight: 700;")
        status_block = QVBoxLayout()
        status_block.addWidget(self.coverage_label)
        status_block.addWidget(self.presence_label)
        header_row.addLayout(status_block)
        layout.addLayout(header_row)

        self.summary_label = QLabel("No correlated patterns yet.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("color: #D6E4FF;")
        layout.addWidget(self.summary_label)

        button_row = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.context_button = QPushButton("Show Context")
        self.snapshot_button = QPushButton("Preserve Evidence Snapshot")
        self.ai_summary_button = QPushButton("Export AI Summary")
        self.logs_button = QPushButton("Open Logs")
        for button in [self.refresh_button, self.context_button, self.snapshot_button, self.ai_summary_button, self.logs_button]:
            button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
            button.setMinimumHeight(36)
            button.setToolTip(button.text())
            button_row.addWidget(button)
        layout.addLayout(button_row)

        self.tabs = QTabWidget()
        self.patterns_tab = QWidget()
        self.timeline_tab = QWidget()
        self.summary_tab = QWidget()
        self._build_patterns_tab()
        self._build_timeline_tab()
        self._build_summary_tab()
        self.tabs.addTab(self.patterns_tab, "Patterns")
        self.tabs.addTab(self.timeline_tab, "Flight Recorder")
        self.tabs.addTab(self.summary_tab, "AI Summary")
        layout.addWidget(self.tabs)

        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.context_button.clicked.connect(self._emit_context)
        self.snapshot_button.clicked.connect(self.snapshot_requested.emit)
        self.ai_summary_button.clicked.connect(self.export_ai_summary_requested.emit)
        self.logs_button.clicked.connect(self.open_logs_requested.emit)
        self.patterns_table.itemSelectionChanged.connect(self._refresh_details)
        self.timeline_table.itemSelectionChanged.connect(self._refresh_details)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a pattern or event to see full details.")
        self.details.setMinimumHeight(220)
        layout.addWidget(QLabel("Details"))
        layout.addWidget(self.details)

    def _build_patterns_tab(self) -> None:
        layout = QVBoxLayout(self.patterns_tab)
        self.patterns_table = _make_table(["Severity", "Confidence", "Title", "Why it matters", "Next steps", "Evidence to preserve"])
        layout.addWidget(self.patterns_table)

    def _build_timeline_tab(self) -> None:
        layout = QVBoxLayout(self.timeline_tab)
        self.timeline_table = _make_table(["Timestamp", "Type", "Severity", "Evidence", "Correlation"])
        layout.addWidget(self.timeline_table)

    def _build_summary_tab(self) -> None:
        layout = QVBoxLayout(self.summary_tab)
        self.ai_summary_view = QTextEdit()
        self.ai_summary_view.setReadOnly(True)
        self.ai_summary_view.setPlaceholderText("The local AI-ready summary appears here.")
        layout.addWidget(self.ai_summary_view)

    def set_report(self, report: IntrusionCorrelationReport | dict[str, Any] | None) -> None:
        self._report = report or {}
        payload = report.to_dict() if hasattr(report, "to_dict") else dict(report or {})
        coverage = payload.get("coverage", {}) or {}
        user_presence = payload.get("user_presence", {}) or {}
        self.coverage_label.setText(str(coverage.get("summary", "Monitoring Coverage: --")))
        self.presence_label.setText(f"User presence: {user_presence.get('state', 'unknown')} ({user_presence.get('reason', 'insufficient data')})")
        self.summary_label.setText(str(payload.get("summary", "No correlated patterns yet.")))
        self._set_patterns(list(payload.get("patterns", [])))
        self._set_timeline(list(payload.get("recent_events", [])))
        self.ai_summary_view.setPlainText(self._format_ai_summary(payload.get("ai_summary", {})))
        has_summary = bool(payload.get("ai_summary"))
        apply_action_state(
            self.ai_summary_button,
            ActionState(
                enabled=has_summary,
                visible=True,
                reason="No local AI-ready summary is available yet. Refresh after scan or monitor events are available.",
                requirements=["scan result or monitor events"],
            ),
        )
        self._refresh_details()

    def _set_patterns(self, patterns: list[dict[str, Any]]) -> None:
        self.patterns_table.setRowCount(0)
        for index, pattern in enumerate(patterns):
            row = self.patterns_table.rowCount()
            self.patterns_table.insertRow(row)
            values = [
                str(pattern.get("severity", "")),
                str(pattern.get("confidence", "")),
                str(pattern.get("title", "")),
                str(pattern.get("why_it_matters", "")),
                ", ".join(str(item) for item in pattern.get("recommended_next_steps", [])),
                ", ".join(str(item) for item in pattern.get("evidence_to_preserve", [])),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, pattern)
                self.patterns_table.setItem(row, column, item)
        self.patterns_table.resizeRowsToContents()

    def _set_timeline(self, events: list[dict[str, Any]]) -> None:
        self.timeline_table.setRowCount(0)
        for event in events:
            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)
            values = [
                str(event.get("timestamp", "")),
                str(event.get("event_type", "")),
                str(event.get("severity", "")),
                str(event.get("evidence", event.get("summary", ""))),
                str(event.get("correlation_id", "")),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, event)
                self.timeline_table.setItem(row, column, item)
        self.timeline_table.resizeRowsToContents()

    def _refresh_details(self) -> None:
        pattern = self._current_item(self.patterns_table)
        event = self._current_item(self.timeline_table)
        if pattern:
            lines = [
                f"Title: {pattern.get('title', '')}",
                f"Severity: {pattern.get('severity', '')}",
                f"Confidence: {pattern.get('confidence', '')}",
                f"Why it matters: {pattern.get('why_it_matters', '')}",
                "Recommended next steps:",
            ]
            lines.extend(f"- {item}" for item in pattern.get("recommended_next_steps", []))
            lines.append("Evidence to preserve:")
            lines.extend(f"- {item}" for item in pattern.get("evidence_to_preserve", []))
            lines.append("False positive notes:")
            lines.extend(f"- {item}" for item in pattern.get("false_positive_notes", []))
            self.details.setPlainText("\n".join(lines))
            apply_action_state(self.context_button, ActionState(enabled=True, visible=True))
            return
        if event:
            lines = [
                f"Timestamp: {event.get('timestamp', '')}",
                f"Type: {event.get('event_type', '')}",
                f"Severity: {event.get('severity', '')}",
                f"Evidence: {event.get('evidence', event.get('summary', ''))}",
                f"Correlation: {event.get('correlation_id', '')}",
            ]
            self.details.setPlainText("\n".join(lines))
            apply_action_state(self.context_button, ActionState(enabled=True, visible=True))
            return
        self.details.setPlainText("No pattern or event selected.")
        apply_action_state(
            self.context_button,
            ActionState(False, visible=False, reason="Select a pattern or timeline event to show context.", requirements=["selected pattern or event"]),
        )

    def _current_item(self, table: QTableWidget) -> dict[str, Any] | None:
        selected = table.currentItem()
        if selected is None:
            return None
        row = selected.row()
        item = table.item(row, 0)
        if item is None:
            return None
        data = item.data(Qt.UserRole)
        return data if isinstance(data, dict) else None

    def _emit_context(self) -> None:
        item = self._current_item(self.patterns_table) or self._current_item(self.timeline_table)
        if item is not None:
            self.show_context_requested.emit(item)

    def _format_ai_summary(self, summary: dict[str, Any]) -> str:
        if not summary:
            return "No local AI-ready summary is available yet."
        lines = [
            f"Generated: {summary.get('generated_at', '')}",
            f"Local only: {'yes' if summary.get('local_only') else 'no'}",
            "",
            "Recommended questions:",
        ]
        lines.extend(f"- {item}" for item in summary.get("recommended_questions", []))
        lines.append("")
        lines.append("Evidence gaps:")
        lines.extend(f"- {item}" for item in summary.get("evidence_gaps", []))
        return "\n".join(lines)
