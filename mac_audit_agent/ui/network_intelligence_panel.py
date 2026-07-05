from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.ui.severity_styles import apply_severity_to_table_item


def _table(headers: list[str]) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SingleSelection)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.setWordWrap(True)
    widget.verticalHeader().setVisible(False)
    widget.horizontalHeader().setStretchLastSection(True)
    return widget


class NetworkIntelligencePanel(QFrame):
    refresh_requested = Signal()
    nmap_requested = Signal()
    local_discovery_requested = Signal()
    settings_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("networkIntelligencePanel")
        self.setFrameShape(QFrame.StyledPanel)
        self._build_ui()
        self.set_snapshot(None)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Network Intelligence")
        title.setStyleSheet("font-size: 20px; font-weight: 800; color: #F0F6FC;")
        subtitle = QLabel("Network Intelligence powered by Network Sentinel, integrated into MSAA storage, alerts, reports, timeline, and settings.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Network Intelligence")
        self.nmap_button = QPushButton("Nmap Local Scan")
        self.discovery_button = QPushButton("Local Network Discovery")
        self.settings_button = QPushButton("Network Settings")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.nmap_button.clicked.connect(self.nmap_requested.emit)
        self.discovery_button.clicked.connect(self.local_discovery_requested.emit)
        self.settings_button.clicked.connect(self.settings_requested.emit)
        for button in [self.refresh_button, self.nmap_button, self.discovery_button, self.settings_button]:
            button.setMinimumHeight(34)
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.disabled_label = QLabel("")
        self.disabled_label.setWordWrap(True)
        self.disabled_label.setStyleSheet("background: #78350F; color: #FFF7ED; padding: 8px; font-weight: 700;")
        layout.addWidget(self.disabled_label)

        self.summary_grid = QGridLayout()
        self.summary_labels: dict[str, QLabel] = {}
        for index, key in enumerate(["Last Scan", "Active Connections", "Listening Ports", "Findings", "Highest Risk", "Baseline Drift", "Gateway", "DNS", "VPN", "Proxy"]):
            name = QLabel(key)
            name.setStyleSheet("color: #9DB0C9; font-weight: 700;")
            value = QLabel("not collected")
            value.setWordWrap(True)
            value.setStyleSheet("color: #F0F6FC;")
            self.summary_labels[key] = value
            row = index // 2
            column = (index % 2) * 2
            self.summary_grid.addWidget(name, row, column)
            self.summary_grid.addWidget(value, row, column + 1)
        layout.addLayout(self.summary_grid)

        layout.addWidget(QLabel("Live Connections"))
        self.connections_table = _table(["Severity", "Process", "PID", "Local Address", "Remote Address", "Port", "State", "Risk"])
        layout.addWidget(self.connections_table)

        layout.addWidget(QLabel("Listening Ports"))
        self.listeners_table = _table(["Severity", "Process", "PID", "Address", "Port", "Service", "Visibility Status", "Risk"])
        layout.addWidget(self.listeners_table)

        layout.addWidget(QLabel("Network Posture"))
        self.posture_table = _table(["Field", "Value"])
        layout.addWidget(self.posture_table)

        layout.addWidget(QLabel("Network Findings"))
        self.findings_table = _table(["Severity", "Finding", "Evidence", "Suggested Fix"])
        layout.addWidget(self.findings_table)

        layout.addWidget(QLabel("Network Timeline"))
        self.timeline_table = _table(["Timestamp", "Severity", "Event", "Evidence"])
        layout.addWidget(self.timeline_table)

        layout.addWidget(QLabel("Diagnostics"))
        self.diagnostics_text = QTextEdit()
        self.diagnostics_text.setReadOnly(True)
        layout.addWidget(self.diagnostics_text)

    def set_snapshot(self, payload: dict[str, Any] | None, *, settings: dict[str, Any] | None = None) -> None:
        settings = settings or {}
        disabled = not bool(settings.get("network_activity_monitoring_enabled", True))
        self.disabled_label.setVisible(disabled)
        self.disabled_label.setText("Network Activity monitoring is disabled in Monitor Settings. Historical Network Intelligence data remains visible." if disabled else "")
        payload = payload or {}
        posture = payload.get("posture", {}) if isinstance(payload.get("posture", {}), dict) else {}
        connections = payload.get("connections", []) if isinstance(payload.get("connections", []), list) else []
        listeners = payload.get("listeners", []) if isinstance(payload.get("listeners", []), list) else []
        findings = payload.get("findings", []) if isinstance(payload.get("findings", []), list) else []
        baseline = payload.get("baseline_comparison", {}) if isinstance(payload.get("baseline_comparison", {}), dict) else {}
        diagnostics = payload.get("diagnostics", {}) if isinstance(payload.get("diagnostics", {}), dict) else {}
        highest = _highest_risk(findings)
        self.summary_labels["Last Scan"].setText(str(payload.get("timestamp", "not collected")))
        self.summary_labels["Active Connections"].setText(str(len(connections)))
        self.summary_labels["Listening Ports"].setText(str(len(listeners)))
        self.summary_labels["Findings"].setText(str(len(findings)))
        self.summary_labels["Highest Risk"].setText(highest)
        self.summary_labels["Baseline Drift"].setText(str(baseline.get("status", "unknown")))
        self.summary_labels["Gateway"].setText(str(posture.get("gateway", "") or "unknown"))
        self.summary_labels["DNS"].setText(", ".join(str(item) for item in posture.get("dns_servers", []) or []) or "unknown")
        self.summary_labels["VPN"].setText("active" if posture.get("vpn_active") else "inactive")
        self.summary_labels["Proxy"].setText("enabled" if posture.get("proxy_enabled") else "disabled")
        self._populate_connections(connections)
        self._populate_listeners(listeners)
        self._populate_posture(posture)
        self._populate_findings(findings)
        self._populate_timeline(payload, findings)
        self.diagnostics_text.setPlainText(_format_diagnostics(diagnostics))

    def _populate_connections(self, rows: list[dict[str, Any]]) -> None:
        values = [
            [
                str(item.get("risk_level", "info")),
                str(item.get("process_name", "")),
                str(item.get("pid", "")),
                f"{item.get('local_address', '')}:{item.get('local_port', '')}",
                str(item.get("remote_address", "")),
                str(item.get("remote_port", "")),
                str(item.get("state", "")),
                str(item.get("evidence", "")) or "Observed connection.",
            ]
            for item in rows
        ] or [["info", "No live connections collected", "", "", "", "", "", "Run Refresh Network Intelligence."]]
        self._populate(self.connections_table, values, severity_column=0)

    def _populate_listeners(self, rows: list[dict[str, Any]]) -> None:
        values = [
            [
                str(item.get("risk_level", "info")),
                str(item.get("process_name", "")),
                str(item.get("pid", "")),
                str(item.get("local_address", "")),
                str(item.get("port", "")),
                str(item.get("service_guess", "")),
                str(item.get("visibility_status", "")),
                str(item.get("evidence", "")) or "Observed listener.",
            ]
            for item in rows
        ] or [["info", "No listening ports collected", "", "", "", "", "", "Run Refresh Network Intelligence."]]
        self._populate(self.listeners_table, values, severity_column=0)

    def _populate_posture(self, posture: dict[str, Any]) -> None:
        rows = [
            ["DNS Servers", ", ".join(str(item) for item in posture.get("dns_servers", []) or []) or "unknown"],
            ["Gateway", str(posture.get("gateway", "") or "unknown")],
            ["VPN", str(posture.get("vpn_name", "")) or ("active" if posture.get("vpn_active") else "inactive")],
            ["Proxy", str(posture.get("proxy_details", "")) or ("enabled" if posture.get("proxy_enabled") else "disabled")],
            ["Interface", str(posture.get("active_interface", "")) or "unknown"],
            ["Local IP", str(posture.get("local_ip", "")) or "unknown"],
        ]
        self._populate(self.posture_table, rows)

    def _populate_findings(self, rows: list[dict[str, Any]]) -> None:
        values = [
            [str(item.get("severity", "info")), str(item.get("title", "")), str(item.get("evidence", "")), str(item.get("suggested_fix", ""))]
            for item in rows
        ] or [["info", "No network findings", "No drift or suspicious network behavior has been collected.", "Run Refresh Network Intelligence or create a baseline."]]
        self._populate(self.findings_table, values, severity_column=0)

    def _populate_timeline(self, payload: dict[str, Any], findings: list[dict[str, Any]]) -> None:
        timestamp = str(payload.get("timestamp", ""))
        values = [[timestamp, str(item.get("severity", "info")), str(item.get("category", "")), str(item.get("evidence", ""))] for item in findings]
        self._populate(self.timeline_table, values or [[timestamp or "not collected", "info", "No network timeline events", "Run Refresh Network Intelligence."]], severity_column=1)

    def _populate(self, table: QTableWidget, rows: list[list[str]], *, severity_column: int | None = None) -> None:
        table.setRowCount(0)
        for values in rows:
            row = table.rowCount()
            table.insertRow(row)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if severity_column is not None and column == severity_column:
                    apply_severity_to_table_item(item, value, text=value.upper())
                table.setItem(row, column, item)
        table.resizeRowsToContents()


def _highest_risk(findings: list[dict[str, Any]]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return max((str(item.get("severity", "info")) for item in findings), key=lambda item: order.get(item, 0), default="info")


def _format_diagnostics(diagnostics: dict[str, Any]) -> str:
    if not diagnostics:
        return "Network Sentinel Integration Health: not collected yet."
    lines = ["Network Sentinel Integration Health"]
    for key in sorted(diagnostics):
        lines.append(f"{key}: {diagnostics[key]}")
    return "\n".join(lines)
