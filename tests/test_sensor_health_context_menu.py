from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from mac_audit_agent.ui.sensor_health_panel import SensorHealthPanel, SensorRepairReportDialog


def _report(*, state: str = "IMPAIRED", remediation: str = "Reconnect the signed sensor and validate event delivery.") -> dict:
    return {
        "overall_health": "DEGRADED",
        "required_sensors_healthy": 0,
        "required_sensors_total": 1,
        "degraded_sensors": 1,
        "failed_sensors": 0,
        "active_recovery_actions": 0,
        "root_causes": [],
        "coverage": [],
        "sensors": [{
            "sensor_id": "endpoint-security",
            "state": state,
            "health_score": 42,
            "reason_code": "IPC_DISCONNECTED",
            "reason": "Authenticated IPC is disconnected.",
            "remediation": remediation,
            "operator_action_required": False,
            "lost_capabilities": ["process execution telemetry"],
            "retained_capabilities": ["filesystem fallback"],
            "last_process_heartbeat": "2026-08-25T00:00:00Z",
            "queue_depth": 0,
            "queue_capacity": 100,
            "events_dropped_total": 0,
            "metadata": {"criticality": "CRITICAL"},
        }],
    }


def _action(menu, object_name: str):
    return next(action for action in menu.actions() if action.objectName() == object_name)


def test_sensor_state_context_menu_exposes_remediation_and_safe_recovery(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    panel = SensorHealthPanel()
    panel.set_report(_report())
    requested: list[str] = []
    panel.recover_requested.connect(requested.append)

    assert panel.table.contextMenuPolicy() == Qt.CustomContextMenu
    assert panel.table.item(0, 0).data(Qt.UserRole + 1)["remediation"].startswith("Reconnect")
    menu = panel._sensor_context_menu(0)
    assert menu is not None
    assert _action(menu, "sensorViewRemediationAction").text() == "View State & Remediation…"

    _action(menu, "sensorCopyRemediationAction").trigger()
    assert QApplication.clipboard().text() == "Reconnect the signed sensor and validate event delivery."
    _action(menu, "sensorCopySurgicalReportAction").trigger()
    assert "MSAA SENSOR SURGICAL REPAIR REPORT" in QApplication.clipboard().text()
    assert "IPC_DISCONNECTED" in QApplication.clipboard().text()
    assert "VERBOSE REPAIR TRACE" not in QApplication.clipboard().text()

    monkeypatch.setattr(QMessageBox, "question", lambda *_args, **_kwargs: QMessageBox.Yes)
    _action(menu, "sensorRecoverAction").trigger()
    assert requested == ["endpoint-security"]
    panel.close()
    app.processEvents()


def test_copyable_sensor_repair_dialog_preserves_verbose_error_text() -> None:
    app = QApplication.instance() or QApplication([])
    text = "REPAIR_WORKFLOW_EXCEPTION: PermissionError: launchd denied the request\nverification=false"
    dialog = SensorRepairReportDialog("Sensor Repair Failed", text)

    dialog.copy_button.click()

    assert QApplication.clipboard().text() == text
    assert dialog.transcript.isReadOnly()
    dialog.close()
    app.processEvents()


def test_permission_blocked_sensor_routes_to_operator_remediation() -> None:
    app = QApplication.instance() or QApplication([])
    panel = SensorHealthPanel()
    report = _report(state="PERMISSION_BLOCKED", remediation="")
    report["sensors"][0]["reason_code"] = "PERMISSION_REQUIRED"
    report["sensors"][0]["operator_action_required"] = True
    panel.set_report(report)

    menu = panel._sensor_context_menu(0)
    assert menu is not None
    recovery = _action(menu, "sensorRecoverAction")
    assert recovery.text() == "View Required Operator Remediation…"
    assert "Restarting alone will not repair" in panel._remediation_for_sensor(report["sensors"][0])
    panel.close()
    app.processEvents()


def test_sensor_summary_only_reports_verified_percentage_from_required_health() -> None:
    app = QApplication.instance() or QApplication([])
    panel = SensorHealthPanel()
    report = _report()
    report["required_sensors_healthy"] = 1
    report["required_sensors_total"] = 2
    panel.set_report(report)

    assert "Verified functional coverage: 50% (1/2)" in panel.summary.text()
    assert panel.recover_all_button.toolTip()
    panel.close()
    app.processEvents()
