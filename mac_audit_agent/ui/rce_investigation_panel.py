from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFormLayout,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


class RCEInvestigationPanel(QFrame):
    """Read-only evidence view with an explicit, audited disposition request."""

    disposition_requested = Signal(str, str, str)

    DISPOSITIONS = (
        "Needs Investigation",
        "Confirmed Exploitation",
        "Probable Exploitation",
        "Suspected Exploitation",
        "Benign Software Behavior",
        "Fuzzing/Test Activity",
        "Debugger Activity",
        "False Positive",
        "Unable to Determine",
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._events: list[dict[str, Any]] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.classification = QLabel("No suspected RCE investigation selected")
        self.classification.setProperty("textRole", "cardTitle")
        self.classification.setWordWrap(True)
        layout.addWidget(self.classification)
        self.boundary = QLabel("Suspected RCE is an investigation classification, not confirmation that exploitation succeeded.")
        self.boundary.setWordWrap(True)
        self.boundary.setProperty("textRole", "muted")
        layout.addWidget(self.boundary)

        self.events = QTableWidget(0, 7)
        self.events.setHorizontalHeaderLabels(["Time", "Classification", "Subtype", "Confidence", "Risk", "Process", "Coverage"])
        self.events.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.events.setSelectionMode(QAbstractItemView.SingleSelection)
        self.events.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.events.setAlternatingRowColors(True)
        self.events.verticalHeader().setVisible(False)
        self.events.horizontalHeader().setStretchLastSection(True)
        self.events.itemSelectionChanged.connect(self._show_selected)
        layout.addWidget(self.events)

        self.tabs = QTabWidget()
        self.why = QTextEdit(); self.why.setReadOnly(True)
        self.evidence = QTextEdit(); self.evidence.setReadOnly(True)
        self.timeline = QTableWidget(0, 4); self.timeline.setHorizontalHeaderLabels(["Time", "Event", "Summary", "Source"])
        self.timeline.setEditTriggers(QAbstractItemView.NoEditTriggers); self.timeline.horizontalHeader().setStretchLastSection(True)
        self.process_tree = QTextEdit(); self.process_tree.setReadOnly(True)
        self.memory = QTextEdit(); self.memory.setReadOnly(True)
        self.files_network = QTextEdit(); self.files_network.setReadOnly(True)
        self.cve_mitre = QTextEdit(); self.cve_mitre.setReadOnly(True)
        self.coverage = QTextEdit(); self.coverage.setReadOnly(True)
        for label, widget in (
            ("Why MSAA Flagged This", self.why), ("Evidence", self.evidence), ("Timeline", self.timeline),
            ("Process Tree", self.process_tree), ("Memory Indicators", self.memory), ("Files & Network", self.files_network),
            ("CVE & MITRE", self.cve_mitre), ("Sensor Coverage", self.coverage),
        ):
            self.tabs.addTab(widget, label)
        layout.addWidget(self.tabs)

        disposition_box = QFrame()
        disposition_form = QFormLayout(disposition_box)
        self.disposition = QComboBox(); self.disposition.addItems(self.DISPOSITIONS)
        self.notes = QLineEdit(); self.notes.setPlaceholderText("Analyst note or evidence/case reference")
        disposition_form.addRow("Analyst disposition", self.disposition)
        disposition_form.addRow("Notes", self.notes)
        layout.addWidget(disposition_box)
        actions = ResponsiveActionRow()
        self.apply_disposition = QPushButton("Record Disposition")
        self.apply_disposition.setMinimumHeight(36)
        self.apply_disposition.clicked.connect(self._request_disposition)
        actions.add_button(self.apply_disposition)
        layout.addWidget(actions)

    def set_events(self, events: list[dict[str, Any]]) -> None:
        self._events = list(events)
        self.events.setRowCount(0)
        for payload in self._events:
            row = self.events.rowCount(); self.events.insertRow(row)
            process = payload.get("process", {}) or payload.get("target_process", {}) or {}
            values = (
                payload.get("observed_at", ""), payload.get("rce_classification", payload.get("event_type", "")),
                payload.get("rce_subtype", ""), f"{str(payload.get('confidence', '')).upper()} ({payload.get('confidence_score', 0)}/100)",
                str(payload.get("risk", payload.get("severity", ""))).upper(), process.get("name") or process.get("executable") or "unknown",
                payload.get("evidence_completeness_label", "UNKNOWN"),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.UserRole, payload)
                self.events.setItem(row, column, item)
        self.events.resizeRowsToContents()
        if self._events:
            self.events.selectRow(0)
        else:
            self._clear()

    def _selected(self) -> dict[str, Any] | None:
        row = self.events.currentRow()
        if row < 0:
            return None
        item = self.events.item(row, 0)
        payload = item.data(Qt.UserRole) if item else None
        return payload if isinstance(payload, dict) else None

    def _show_selected(self) -> None:
        payload = self._selected()
        if payload is None:
            self._clear(); return
        classification = str(payload.get("rce_classification", payload.get("event_type", ""))).replace("_", " ")
        self.classification.setText(classification)
        why = str(payload.get("why_flagged", "Evidence was preserved for investigation."))
        benign = [str(item) for item in payload.get("possible_benign_explanations", [])]
        self.why.setPlainText(why + ("\n\nContext reducing confidence:\n- " + "\n- ".join(benign) if benign else ""))
        reasons = payload.get("reason_evidence", [])
        self.evidence.setPlainText("\n".join(f"{item.get('code', '')}  {item.get('confidence_contribution', 0):+} — {item.get('description', '')}\nSource: {item.get('telemetry_source', '')} at {item.get('observed_at', '')}" for item in reasons) or "No structured reason evidence is available.")
        timeline = payload.get("timeline", [])
        self.timeline.setRowCount(0)
        for entry in timeline:
            row = self.timeline.rowCount(); self.timeline.insertRow(row)
            for column, value in enumerate((entry.get("timestamp", ""), entry.get("event_type", ""), entry.get("summary", ""), entry.get("source", ""))):
                self.timeline.setItem(row, column, QTableWidgetItem(str(value)))
        ancestry = [payload.get("source_process", {}), *payload.get("process_ancestry", []), payload.get("parent_process", {}), payload.get("process", {})]
        self.process_tree.setPlainText("\n  ↓\n".join(self._process_line(item) for item in ancestry if item) or "Process ancestry unavailable.")
        memory = payload.get("memory_context", {})
        primitives = [item for item in payload.get("exploit_primitives", []) if item.get("category") in {"memory_corruption", "stack_corruption", "heap_corruption", "control_flow_anomaly", "executable_memory", "write_then_execute"}]
        self.memory.setPlainText(self._key_values(memory, primitives))
        self.files_network.setPlainText("Files\n" + self._key_values(payload.get("file_context", {})) + "\n\nNetwork\n" + self._key_values(payload.get("network_context", {})))
        cves = payload.get("cve_correlations", [])
        attacks = payload.get("attack_mappings", [])
        self.cve_mitre.setPlainText("CVE behavioral similarities\n" + self._key_values(cves) + "\n\nMITRE ATT&CK defensive context\n" + self._key_values(attacks))
        coverage = payload.get("sensor_coverage", {})
        gaps = payload.get("telemetry_gaps", [])
        self.coverage.setPlainText("\n".join(f"{key}: {value}" for key, value in coverage.items()) + ("\n\nWARNING — evidence may be incomplete:\n- " + "\n- ".join(str(item) for item in gaps) if gaps else ""))

    @staticmethod
    def _process_line(process: dict[str, Any]) -> str:
        return f"{process.get('executable') or process.get('name') or 'unknown'}  PID {process.get('pid', '?')}  PPID {process.get('ppid', '?')}  signer {process.get('signing_status', 'unknown')}  Team ID {process.get('team_id', 'unknown')}"

    @staticmethod
    def _key_values(value: Any, extra: Any = None) -> str:
        values = []
        if isinstance(value, dict):
            values.extend(f"{key}: {item}" for key, item in value.items() if key != "registers")
        elif isinstance(value, list):
            values.extend(str(item) for item in value)
        if extra:
            values.extend(str(item) for item in extra)
        return "\n".join(values) or "No evidence available from current sensors."

    def _request_disposition(self) -> None:
        payload = self._selected()
        if payload:
            self.disposition_requested.emit(str(payload.get("event_id", "")), self.disposition.currentText(), self.notes.text().strip())

    def _clear(self) -> None:
        self.classification.setText("No suspected RCE investigation selected")
        for widget in (self.why, self.evidence, self.process_tree, self.memory, self.files_network, self.cve_mitre, self.coverage):
            widget.clear()
        self.timeline.setRowCount(0)


__all__ = ["RCEInvestigationPanel"]
