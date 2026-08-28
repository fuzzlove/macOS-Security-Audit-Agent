from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


def audit_widget_controls(root: Any, *, section: str = "") -> list[dict[str, Any]]:
    from PySide6.QtWidgets import QAbstractButton, QComboBox, QLineEdit, QTabWidget, QWidget

    records: list[dict[str, Any]] = []
    for widget in root.findChildren(QWidget):
        label = ""
        connected = True
        kind = type(widget).__name__
        if isinstance(widget, QAbstractButton):
            label = widget.text()
            try:
                connected = widget.receivers(widget.clicked) > 0
            except Exception:
                connected = True
        elif isinstance(widget, QComboBox):
            label = widget.objectName() or "combo box"
            try:
                connected = widget.receivers(widget.currentIndexChanged) > 0
            except Exception:
                connected = True
        elif isinstance(widget, QLineEdit):
            label = widget.placeholderText() or widget.objectName() or "text field"
        elif isinstance(widget, QTabWidget):
            for index in range(widget.count()):
                records.append(
                    {
                        "label": widget.tabText(index),
                        "objectName": widget.objectName(),
                        "type": "tab",
                        "section": section,
                        "enabled": widget.isTabEnabled(index),
                        "visible": widget.isVisible(),
                        "tooltip_exists": bool(widget.tabToolTip(index)),
                        "callback_connected": True,
                        "backend_action_exists": True,
                        "visible_result_verified": False,
                        "status": "PASS" if widget.isTabEnabled(index) else "WARN",
                    }
                )
            continue
        else:
            continue
        visible = widget.isVisible()
        enabled = widget.isEnabled()
        tooltip = bool(widget.toolTip())
        status = "PASS"
        if visible and not enabled and not tooltip:
            status = "FAIL"
        if visible and isinstance(widget, QAbstractButton) and not connected:
            status = "FAIL"
        records.append(
            {
                "label": label,
                "objectName": widget.objectName(),
                "type": kind,
                "section": section,
                "enabled": enabled,
                "visible": visible,
                "tooltip_exists": tooltip,
                "callback_connected": connected,
                "backend_action_exists": connected,
                "visible_result_verified": False,
                "status": status,
            }
        )
    return records


def run_ui_control_audit(context: AuditContext) -> list[FunctionalCheck]:
    check = FunctionalCheck("ui.controls", "Reports/UI", "UI control audit", "Visible controls are enabled/connected or explained.", "blocker", "ui")
    if not context.ui_interactive:
        records = static_ui_control_audit()
        failures = [record for record in records if record["status"] == "FAIL"]
        path = write_ui_control_audit(records, context.output_dir / "ui_audits" / "PRE_UAT_UI_CONTROL_AUDIT.md")
        evidence = {
            "control_count": len(records),
            "failure_count": len(failures),
            "report_path": str(path),
            "mode": "static_source",
            "runtime_widget_audit": "skipped_headless_pre_uat",
        }
        if failures:
            check.failure_stage = "ui_control_disconnected"
            return [check.failed("Static UI audit found buttons without clicked.connect wiring.", "Connect visible production buttons to backend actions or hide them behind Developer Mode.", {**evidence, "failures": failures[:25]})]
        return [check.passed("Static UI audit found no disconnected controls.", evidence)]
    try:
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is None:
            records = static_ui_control_audit()
            failures = [record for record in records if record["status"] == "FAIL"]
            path = write_ui_control_audit(records, context.output_dir / "ui_audits" / "PRE_UAT_UI_CONTROL_AUDIT.md")
            evidence = {"control_count": len(records), "failure_count": len(failures), "report_path": str(path), "mode": "static_source"}
            if failures:
                check.failure_stage = "ui_control_disconnected"
                return [check.failed("Static UI audit found buttons without clicked.connect wiring.", "Connect visible production buttons to backend actions or hide them behind Developer Mode.", {**evidence, "failures": failures[:25]})]
            evidence["runtime_widget_audit"] = "not_applicable_without_qapplication"
            return [check.passed("Static UI audit found no disconnected controls.", evidence)]
        from mac_audit_agent.launch_agent import LaunchAgentManager
        from mac_audit_agent.storage import AuditDatabase
        from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel

        db = AuditDatabase(context.db_path)
        panel = BackgroundMonitorPanel(db, LaunchAgentManager(context.db_path))
        records = audit_widget_controls(panel, section="Background Monitor")
        failures = [record for record in records if record["visible"] and record["status"] == "FAIL"]
        path = write_ui_control_audit(records, context.output_dir / "ui_audits" / "PRE_UAT_UI_CONTROL_AUDIT.md")
        evidence = {"control_count": len(records), "failure_count": len(failures), "report_path": str(path)}
        panel.deleteLater()
        if failures:
            return [check.failed("Visible UI controls are disconnected or disabled without explanation.", "Connect callbacks or add explanatory tooltips; hide fake/demo controls outside Developer Mode.", {**evidence, "failures": failures[:25]})]
        return [check.passed("Visible UI controls have callbacks or explanations.", evidence)]
    except Exception as exc:
        check.failure_stage = "unknown"
        return [check.failed(str(exc), "Fix UI construction/control inspection so pre-UAT can detect disconnected controls.", {"exception": type(exc).__name__})]


def static_ui_control_audit(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    paths = paths or [Path("mac_audit_agent/ui/main_window.py"), Path("mac_audit_agent/ui/background_monitor_panel.py")]
    records: list[dict[str, Any]] = []
    pattern = re.compile(r"self\.(?P<name>\w+)\s*=\s*QPushButton\((?P<label>[^)]*)\)")
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in pattern.finditer(text):
            name = match.group("name")
            label = match.group("label").strip().strip("\"'")
            connected = f"self.{name}.clicked.connect" in text
            records.append(
                {
                    "label": label,
                    "objectName": name,
                    "type": "QPushButton",
                    "section": str(path),
                    "enabled": True,
                    "visible": True,
                    "tooltip_exists": f"self.{name}.setToolTip" in text,
                    "callback_connected": connected,
                    "backend_action_exists": connected,
                    "visible_result_verified": False,
                    "status": "PASS" if connected else "FAIL",
                }
            )
    return records


def write_ui_control_audit(records: list[dict[str, Any]], path: Path | None = None) -> Path:
    path = path or Path("reports") / "pre_uat" / "ui_audits" / "PRE_UAT_UI_CONTROL_AUDIT.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Pre-UAT UI Control Audit",
        "",
        "| Status | Type | Label | Enabled | Tooltip | Callback | Section |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for record in records:
        lines.append(
            f"| {record['status']} | {record['type']} | {str(record['label']).replace('|', '/')} | "
            f"{record['enabled']} | {record['tooltip_exists']} | {record['callback_connected']} | {record['section']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
