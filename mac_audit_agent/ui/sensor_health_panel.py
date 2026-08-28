"""Operator-facing sensor function and security-coverage dashboard."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QFrame, QHBoxLayout, QLabel, QMenu,
    QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from mac_audit_agent.health.surgical_repair import build_surgical_repair_plan, render_surgical_repair_transcript
from mac_audit_agent.ui.button_factory import create_export_button, create_repair_button, create_toolbar_button
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


class SensorRepairReportDialog(QDialog):
    """Copy-friendly repair plan/outcome without hiding verification failures."""

    def __init__(self, title: str, transcript: str, *, allow_repair: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(920, 720)
        layout = QVBoxLayout(self)
        heading = QLabel(title)
        heading.setProperty("textRole", "cardTitle")
        note = QLabel("The report below is plain text so the complete diagnosis, repair trace, and exact blockers can be copied into a support case.")
        note.setWordWrap(True)
        note.setProperty("textRole", "muted")
        self.transcript = QTextEdit()
        self.transcript.setObjectName("sensorSurgicalRepairTranscript")
        self.transcript.setReadOnly(True)
        self.transcript.setLineWrapMode(QTextEdit.NoWrap)
        self.transcript.setPlainText(transcript)
        actions = ResponsiveActionRow()
        self.copy_button = create_toolbar_button("Copy Full Repair Report", tooltip="Copy the complete plain-text diagnosis, trace, errors, and verification result.")
        self.copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.transcript.toPlainText()))
        actions.add_button(self.copy_button)
        self.repair_button = create_repair_button("Run Bounded Surgical Repair", tooltip="Run only the policy-approved repair, followed by a functional self-test and independent health snapshot.")
        self.repair_button.setVisible(allow_repair)
        self.repair_button.clicked.connect(self.accept)
        actions.add_button(self.repair_button)
        close_button = create_toolbar_button("Close", tooltip="Close this report without changing the sensor.")
        close_button.clicked.connect(self.reject)
        actions.add_button(close_button)
        layout.addWidget(heading)
        layout.addWidget(note)
        layout.addWidget(self.transcript, 1)
        layout.addWidget(actions)


class SensorHealthPanel(QFrame):
    refresh_requested = Signal()
    self_test_requested = Signal()
    export_requested = Signal()
    recover_requested = Signal(str)
    recover_all_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._report: dict[str, Any] = {}
        self.setObjectName("sensorHealthPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        title = QLabel("MSAA Sensor Health")
        title.setProperty("textRole", "cardTitle")
        subtitle = QLabel("Functional coverage, telemetry flow, dependencies, permissions, queues, event loss, and recovery evidence. Process liveness alone never produces a healthy result.")
        subtitle.setWordWrap(True)
        subtitle.setProperty("textRole", "muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        self.summary = QLabel("Health assurance has not run yet.")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet("font-weight: 700; padding: 8px;")
        layout.addWidget(self.summary)
        self.explanation = QLabel("MSAA will report only the coverage supported by current functional evidence.")
        self.explanation.setWordWrap(True)
        layout.addWidget(self.explanation)
        actions = ResponsiveActionRow()
        self.refresh_button = create_toolbar_button("Refresh Sensor Health", tooltip="Run bounded, isolated functional health checks without restarting healthy sensors.")
        self.test_button = create_toolbar_button("Run Health Test", tooltip="Run harmless tagged process, filesystem, IPC, and lightweight database probes where supported.")
        self.recover_button = create_repair_button("Surgical Repair Selected Sensor", tooltip="Open a complete diagnosis, then run the least-disruptive policy-approved repair with functional verification and a copyable trace.")
        self.recover_all_button = create_repair_button("Repair All Repairable Sensors", tooltip="Repair recoverable sensors in dependency order, then run independent post-repair self-tests. External permission, entitlement, and signing blockers remain explicit.")
        self.export_button = create_export_button("Export Diagnostics", tooltip="Export sanitized sensor status, transitions, dependencies, and recovery history as HTML, DOCX, XLSX, or JSON.")
        for button in (self.refresh_button, self.test_button, self.recover_button, self.recover_all_button, self.export_button):
            actions.add_button(button)
        layout.addWidget(actions)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(("Sensor", "State", "Coverage", "Last Event", "Latency", "Drops", "Recovery"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_sensor_context_menu)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 2)
        coverage_title = QLabel("Security Capability Coverage")
        coverage_title.setProperty("textRole", "sectionTitle")
        layout.addWidget(coverage_title)
        self.coverage_table = QTableWidget(0, 4)
        self.coverage_table.setHorizontalHeaderLabels(("Capability", "Coverage", "Reason", "Fallback"))
        self.coverage_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.coverage_table.setAlternatingRowColors(True)
        self.coverage_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.coverage_table, 1)
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.test_button.clicked.connect(self.self_test_requested.emit)
        self.export_button.clicked.connect(self.export_requested.emit)
        self.recover_button.clicked.connect(self._recover_selected)
        self.recover_all_button.clicked.connect(self.recover_all_requested.emit)

    def set_report(self, report: dict[str, Any]) -> None:
        self._report = dict(report or {})
        overall = str(report.get("overall_health", "UNKNOWN"))
        required = f"{report.get('required_sensors_healthy', 0)}/{report.get('required_sensors_total', 0)}"
        required_total = int(report.get("required_sensors_total", 0) or 0)
        required_healthy = int(report.get("required_sensors_healthy", 0) or 0)
        verified_percent = round(required_healthy / required_total * 100) if required_total else 0
        self.summary.setText(
            f"Overall: {overall}  |  Verified functional coverage: {verified_percent}% ({required})  |  "
            f"Degraded: {report.get('degraded_sensors', 0)}  |  Failed: {report.get('failed_sensors', 0)}  |  "
            f"Active recovery: {report.get('active_recovery_actions', 0)}"
        )
        roots = report.get("root_causes", [])
        if roots:
            root = roots[0]
            self.explanation.setText(f"Root cause: {root.get('dependency', 'shared dependency')} affects {root.get('affected_count', 0)} sensor(s). Independent capabilities retain their own status.")
        elif overall == "HEALTHY":
            self.explanation.setText("All required sensors have current functional evidence. This is not an absolute security guarantee.")
        else:
            self.explanation.setText("Open a sensor row for the precise lost and retained coverage. MSAA does not present fallback telemetry as equivalent coverage.")
        sensors = list(report.get("sensors", []))
        self.table.setRowCount(len(sensors))
        for row, sensor in enumerate(sensors):
            lost = [str(item) for item in sensor.get("lost_capabilities", []) if str(item)]
            retained = [str(item) for item in sensor.get("retained_capabilities", []) if str(item)]
            coverage = "Full" if not lost and str(sensor.get("state", "UNKNOWN")).upper() in {"HEALTHY", "HEALTHY_IDLE", "HEALTHY_WITH_WARNINGS"} else f"{len(lost)} lost / {len(retained)} retained" if lost or retained else "Unknown"
            activity = [
                str(sensor.get(key, ""))
                for key in ("last_collection_activity", "last_processing_activity", "last_delivery_activity", "last_persistence_activity")
                if sensor.get(key)
            ]
            last_event = max(activity) if activity else sensor.get("last_process_heartbeat", "—")
            latency = sensor.get("processing_latency_ms")
            latency_text = f"{float(latency):.1f} ms" if isinstance(latency, (int, float)) else "—"
            state = str(sensor.get("state", "UNKNOWN")).upper()
            recovery = "Operator action" if sensor.get("operator_action_required") else "Available" if state not in {"HEALTHY", "HEALTHY_IDLE"} else "Not required"
            values = (
                sensor.get("sensor_id", ""), sensor.get("state", "UNKNOWN"), coverage,
                last_event, latency_text, sensor.get("events_dropped_total", 0), recovery,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, sensor.get("sensor_id", ""))
                item.setData(Qt.UserRole + 1, dict(sensor))
                item.setToolTip(str(sensor.get("reason", "No additional sensor explanation was supplied.")))
                self.table.setItem(row, column, item)
        coverage = list(report.get("coverage", []))
        self.coverage_table.setRowCount(len(coverage))
        for row, item in enumerate(coverage):
            for column, value in enumerate((item.get("capability_id", ""), item.get("coverage", "UNKNOWN"), item.get("reason", ""), item.get("fallback", ""))):
                self.coverage_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.table.resizeRowsToContents()
        self.coverage_table.resizeRowsToContents()

    def _recover_selected(self) -> None:
        row = self.table.currentRow()
        sensor = self._sensor_for_row(row)
        if sensor is None:
            QMessageBox.information(self, "Select a Sensor", "Select one sensor row before requesting recovery.")
            return
        sensor_id = str(sensor.get("sensor_id", ""))
        state = str(sensor.get("state", "UNKNOWN")).upper()
        operator_required = bool(sensor.get("operator_action_required")) or state in {"PERMISSION_BLOCKED", "UNSUPPORTED"}
        if self._open_surgical_repair(sensor, allow_repair=not operator_required):
            self.recover_requested.emit(sensor_id)

    def _sensor_for_row(self, row: int) -> dict[str, Any] | None:
        item = self.table.item(row, 0) if row >= 0 else None
        payload = item.data(Qt.UserRole + 1) if item is not None else None
        if isinstance(payload, dict):
            return dict(payload)
        return None

    @staticmethod
    def _remediation_for_sensor(sensor: dict[str, Any]) -> str:
        supplied = str(sensor.get("remediation", "")).strip()
        if supplied:
            return supplied
        state = str(sensor.get("state", "UNKNOWN")).upper()
        reason_code = str(sensor.get("reason_code", "")).upper()
        if state in {"HEALTHY", "HEALTHY_IDLE"}:
            return "No repair is indicated. Keep monitoring current and run a safe self-test after material configuration changes."
        if state == "HEALTHY_WITH_WARNINGS":
            return "Review the warning and retained/lost capability evidence before changing the sensor. Run a safe self-test to confirm functional coverage."
        if state == "PERMISSION_BLOCKED" or "PERMISSION" in reason_code or "ENTITLEMENT" in reason_code:
            return "Review the sensor's required macOS permission or entitlement. Grant only the documented access to the signed MSAA component, then refresh health and run a safe self-test. Restarting alone will not repair a denied permission."
        if state == "UNSUPPORTED":
            return "This sensor is unsupported in the current OS, hardware, or runtime context. Do not repeatedly restart it; use the reported fallback and review supported deployment requirements."
        if "SIGNATURE" in reason_code:
            return "Preserve diagnostics and reinstall or repair the sensor from a trusted signed MSAA source. Do not bypass signature validation."
        if state == "CONFIGURATION_ERROR" or "CONFIG" in reason_code:
            return "Compare the observed and expected configuration evidence, restore only an approved known-good configuration, then refresh and run a safe self-test."
        if state == "DEPENDENCY_FAILED" or "DEPENDENCY" in reason_code:
            return "Repair the named dependency first, then refresh this sensor. Avoid restarting every sensor in the shared failure domain."
        if state in {"BACKPRESSURED", "HIGH_LOAD", "RATE_LIMITED"} or any(marker in reason_code for marker in ("QUEUE", "RESOURCE", "PRESSURE")):
            return "Export diagnostics, inspect queue depth, event loss, storage latency, and resource pressure, then use bounded recovery only after preserving evidence."
        if state in {"FAILED", "IMPAIRED", "STALE", "DEGRADED", "UNAVAILABLE"}:
            return "Run a safe self-test, preserve diagnostics, and request the least-disruptive sensor recovery. Refresh health afterward to verify that functional coverage—not only process liveness—returned."
        return "Export diagnostics, run a safe self-test, and review the sensor reason, dependencies, permissions, and lost capabilities before requesting recovery."

    def _sensor_context_menu(self, row: int) -> QMenu | None:
        sensor = self._sensor_for_row(row)
        if sensor is None:
            return None
        sensor_id = str(sensor.get("sensor_id", ""))
        state = str(sensor.get("state", "UNKNOWN")).upper()
        operator_required = bool(sensor.get("operator_action_required")) or state in {"PERMISSION_BLOCKED", "UNSUPPORTED"}
        menu = QMenu(self)
        details_action = menu.addAction("View State & Remediation…")
        details_action.setObjectName("sensorViewRemediationAction")
        details_action.triggered.connect(lambda _checked=False: self._show_sensor_remediation(sensor))
        copy_action = menu.addAction("Copy Remediation Guidance")
        copy_action.setObjectName("sensorCopyRemediationAction")
        copy_action.triggered.connect(lambda _checked=False: QApplication.clipboard().setText(self._remediation_for_sensor(sensor)))
        verbose_copy = menu.addAction("Copy Full Surgical Repair Report")
        verbose_copy.setObjectName("sensorCopySurgicalReportAction")
        verbose_copy.triggered.connect(
            lambda _checked=False: QApplication.clipboard().setText(render_surgical_repair_transcript(sensor))
        )
        menu.addSeparator()
        test_action = menu.addAction("Run Safe Sensor Self-Tests")
        test_action.setObjectName("sensorRunSelfTestsAction")
        test_action.triggered.connect(lambda _checked=False: self.self_test_requested.emit())
        recovery_text = "View Required Operator Remediation…" if operator_required else "Request Safe Recovery…"
        recover_action = menu.addAction(recovery_text)
        recover_action.setObjectName("sensorRecoverAction")
        healthy = state in {"HEALTHY", "HEALTHY_IDLE"}
        recover_action.setEnabled(not healthy)
        if operator_required:
            recover_action.triggered.connect(lambda _checked=False: self._show_sensor_remediation(sensor))
        else:
            recover_action.triggered.connect(lambda _checked=False: self._confirm_sensor_recovery(sensor_id, state))
        menu.addSeparator()
        refresh_action = menu.addAction("Refresh Sensor Health")
        refresh_action.setObjectName("sensorRefreshAction")
        refresh_action.triggered.connect(lambda _checked=False: self.refresh_requested.emit())
        export_action = menu.addAction("Export Sensor Diagnostics…")
        export_action.setObjectName("sensorExportDiagnosticsAction")
        export_action.triggered.connect(lambda _checked=False: self.export_requested.emit())
        return menu

    def _show_sensor_context_menu(self, position) -> None:
        row = self.table.rowAt(position.y())
        if row < 0:
            return
        self.table.selectRow(row)
        menu = self._sensor_context_menu(row)
        if menu is not None:
            menu.exec(self.table.viewport().mapToGlobal(position))

    def _show_sensor_remediation(self, sensor: dict[str, Any]) -> None:
        enriched = dict(sensor)
        enriched["remediation"] = self._remediation_for_sensor(sensor)
        self._open_surgical_repair(enriched, allow_repair=False)

    def _open_surgical_repair(self, sensor: dict[str, Any], *, allow_repair: bool) -> bool:
        enriched = dict(sensor)
        enriched["remediation"] = self._remediation_for_sensor(sensor)
        plan = build_surgical_repair_plan(enriched)
        dialog = SensorRepairReportDialog(
            f"Surgical Sensor Repair — {plan['sensor_id']}",
            render_surgical_repair_transcript(enriched),
            allow_repair=allow_repair,
            parent=self,
        )
        return dialog.exec() == QDialog.Accepted

    def show_repair_result(self, payload: dict[str, Any]) -> None:
        sensor = payload.get("pre_repair_snapshot") if isinstance(payload.get("pre_repair_snapshot"), dict) else {
            "sensor_id": payload.get("sensor_id", "unknown"),
            "state": "UNKNOWN",
            "reason_code": payload.get("reason_code", "UNKNOWN"),
        }
        transcript = str(payload.get("copyable_transcript", "")) or render_surgical_repair_transcript(sensor, payload)
        SensorRepairReportDialog(
            f"Sensor Repair Outcome — {payload.get('sensor_id', 'unknown')}",
            transcript,
            parent=self,
        ).exec()

    def show_repair_failure(self, sensor_id: str, error: Exception) -> None:
        sensor = {
            "sensor_id": sensor_id or "unknown",
            "state": "REPAIR_FAILED",
            "reason_code": "REPAIR_WORKFLOW_EXCEPTION",
            "reason": f"{type(error).__name__}: {error}",
            "remediation": "Copy this report for support, preserve current diagnostics, and do not repeatedly restart the sensor until the exception is understood.",
            "operator_action_required": True,
        }
        payload = {
            "sensor_id": sensor_id,
            "recovery": {"attempted": True, "succeeded": False, "action": "WORKFLOW", "detail": sensor["reason"], "requires_operator": True},
            "post_recovery_state": "UNKNOWN",
            "fully_operational": False,
            "errors": [sensor["reason"]],
        }
        SensorRepairReportDialog(
            f"Sensor Repair Failed — {sensor_id or 'unknown'}",
            render_surgical_repair_transcript(sensor, payload),
            parent=self,
        ).exec()

    def show_repair_all_result(self, payload: dict[str, Any]) -> None:
        lines = [
            "MSAA SURGICAL REPAIR — ALL REPAIRABLE SENSORS",
            f"Sensors considered: {payload.get('attempted_sensors', 0)}",
            f"Verified fully operational: {payload.get('verified_sensors', 0)}",
            f"Operator actions required: {payload.get('operator_action_required', 0)}",
            f"All required sensors at verified functional coverage: {bool(payload.get('fully_operational', False))}",
            "",
        ]
        for result in payload.get("results", []):
            if not isinstance(result, dict):
                continue
            transcript = str(result.get("copyable_transcript", "")).strip()
            if not transcript:
                sensor = result.get("pre_repair_snapshot") if isinstance(result.get("pre_repair_snapshot"), dict) else {
                    "sensor_id": result.get("sensor_id", "unknown"),
                    "state": "UNKNOWN",
                    "reason_code": result.get("reason_code", "UNKNOWN"),
                }
                transcript = render_surgical_repair_transcript(sensor, result).strip()
            lines.extend(("=" * 78, transcript, ""))
        SensorRepairReportDialog("All-Sensor Surgical Repair Outcome", "\n".join(lines), parent=self).exec()

    def _confirm_sensor_recovery(self, sensor_id: str, state: str) -> None:
        if not sensor_id:
            return
        if QMessageBox.question(
            self,
            "Request Safe Sensor Recovery?",
            f"Request the least-disruptive policy-approved recovery for {sensor_id} ({state})?\n\n"
            "MSAA will preserve recovery evidence and validate the result when supported. Permission, entitlement, signing, and unsupported-platform conditions still require operator action.",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        ) == QMessageBox.Yes:
            self.recover_requested.emit(sensor_id)


__all__ = ["SensorHealthPanel", "SensorRepairReportDialog"]
