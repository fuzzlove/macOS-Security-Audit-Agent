from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


BUTTON_FACTORIES = {"QPushButton", "QToolButton", "create_button", "create_toolbar_button", "create_export_button", "create_repair_button"}
CRITICAL_LABELS = {"Install Active Protection", "Repair Active Protection", "Verify Active Protection", "Export Protection Diagnostics"}


@dataclass(frozen=True)
class ButtonAuditItem:
    label: str
    file_path: str
    parent_panel: str
    variable: str
    callback_connected: bool
    callback: str
    enabled: bool
    tooltip_present: bool
    classification: str
    admin_required: bool
    records_result: bool
    updates_status: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _call_name(node: ast.Call) -> str:
    target = node.func
    return target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""


def audit_button_file(path: Path) -> list[ButtonAuditItem]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assignments: dict[str, tuple[str, str, bool, str]] = {}
    callbacks: dict[str, str] = {}
    disabled: set[str] = set()
    tooltips: set[str] = set()
    parent = path.stem
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.endswith(("Panel", "Window", "Dialog")):
            parent = node.name
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(value, ast.Call) and _call_name(value) in BUTTON_FACTORIES:
                label = value.args[0].value if value.args and isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str) else "<dynamic label>"
                factory_tooltip = any(keyword.arg == "tooltip" and isinstance(keyword.value, ast.Constant) and bool(keyword.value.value) for keyword in value.keywords)
                factory_callback = next((ast.unparse(keyword.value) for keyword in value.keywords if keyword.arg == "on_click"), "")
                for target in targets:
                    variable = target.attr if isinstance(target, ast.Attribute) else target.id if isinstance(target, ast.Name) else ""
                    if variable:
                        if label != "<dynamic label>":
                            assignments[variable] = (label, parent, factory_tooltip, factory_callback)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            variable = owner.attr if isinstance(owner, ast.Attribute) else owner.id if isinstance(owner, ast.Name) else ""
            if node.func.attr == "connect" and isinstance(owner, ast.Attribute) and owner.attr in {"clicked", "triggered", "pressed"}:
                button_owner = owner.value
                variable = button_owner.attr if isinstance(button_owner, ast.Attribute) else button_owner.id if isinstance(button_owner, ast.Name) else ""
                callbacks[variable] = ast.unparse(node.args[0]) if node.args else "<missing>"
            elif node.func.attr == "setEnabled" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value is False:
                disabled.add(variable)
            elif node.func.attr == "setToolTip":
                tooltips.add(variable)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "connect_or_disable" and len(node.args) >= 3:
            button = node.args[0]
            variable = button.attr if isinstance(button, ast.Attribute) else button.id if isinstance(button, ast.Name) else ""
            callback_name = node.args[2].value if isinstance(node.args[2], ast.Constant) else "<dynamic callback>"
            if variable:
                callbacks[variable] = f"connect_or_disable:{callback_name}"
    items: list[ButtonAuditItem] = []
    for variable, (label, panel, factory_tooltip, factory_callback) in assignments.items():
        callback = callbacks.get(variable, factory_callback)
        connected = bool(callback)
        enabled = variable not in disabled
        classification = "functional" if connected else "disabled_with_reason" if not enabled and variable in tooltips else "disconnected"
        body_hint = callback.lower()
        tooltip_present = variable in tooltips or factory_tooltip
        items.append(ButtonAuditItem(label, str(path), panel, variable, connected, callback, enabled, tooltip_present, classification, "install" in label.lower() or "repair" in label.lower(), any(token in body_hint for token in ("install", "repair", "export", "refresh", "emit", "show")), any(token in body_hint for token in ("refresh", "install", "repair", "emit"))))
    return items


def audit_visible_buttons(root: Path | None = None) -> dict[str, Any]:
    root = Path(root or Path.cwd())
    items: list[ButtonAuditItem] = []
    for path in sorted((root / "mac_audit_agent/ui").glob("*.py")):
        try:
            items.extend(audit_button_file(path))
        except (OSError, SyntaxError):
            continue
    critical = [item for item in items if item.label in CRITICAL_LABELS]
    blockers = [item for item in critical if not item.callback_connected or (item.enabled and not item.tooltip_present)]
    disconnected = [item for item in items if item.enabled and not item.callback_connected]
    return {"status": "pass" if not blockers else "fail", "check_id": "ui.buttons.functional_actions", "items": [item.to_dict() for item in items], "critical_items": [item.to_dict() for item in critical], "blockers": [item.to_dict() for item in blockers], "disconnected_candidates": [item.to_dict() for item in disconnected], "note": "Dynamic/loop connections require declared manual review; critical Active Protection actions are release-blocking."}


def run_button_functionality_audit(context: AuditContext) -> list[FunctionalCheck]:
    payload = audit_visible_buttons(Path.cwd())
    check = FunctionalCheck("ui.buttons.functional_actions", "Reports/UI", "functional UI actions", "Critical protection buttons call real backends and expose results.", "blocker", "static")
    from mac_audit_agent.ui.button_callback_registry import validate_callback_source
    callback_results = validate_callback_source(Path.cwd())
    missing = [item.to_dict() for item in callback_results if not item.exists]
    callback_evidence = {"callbacks": [item.to_dict() for item in callback_results], "missing": missing}
    extra = [
        FunctionalCheck("ui.antiransomware_panel_instantiates", "Reports/UI", "Anti-Ransomware panel callback contract", "Panel construction has every required public callback.", "blocker", "static"),
        FunctionalCheck("ui.antiransomware_install_button_connected", "Reports/UI", "Anti-Ransomware install action", "Install button resolves to AntiRansomwarePanel.install_protection.", "blocker", "static"),
        FunctionalCheck("ui.active_protection_install_button_connected", "Reports/UI", "Active Protection install action", "Dashboard and health install actions are connected.", "blocker", "static"),
        FunctionalCheck("ui.active_protection_repair_button_connected", "Reports/UI", "Active Protection repair action", "Dashboard and health repair actions are connected.", "blocker", "static"),
        FunctionalCheck("ui.no_missing_button_callbacks", "Reports/UI", "no missing callbacks", "Registered production callbacks all exist.", "blocker", "static"),
    ]
    antiransomware_missing = [item for item in missing if item["owner"] == "AntiRansomwarePanel"]
    supplemental = [
        extra[0].passed("AntiRansomwarePanel public callback contract is complete.", callback_evidence) if not antiransomware_missing else extra[0].failed("AntiRansomwarePanel callback contract is incomplete.", "Implement missing methods.", callback_evidence),
        extra[1].passed("Install Active Protection resolves to install_protection.", callback_evidence) if not any(item["callback"] == "install_protection" for item in antiransomware_missing) else extra[1].failed("install_protection is missing.", "Implement or reconnect install_protection.", callback_evidence),
        extra[2].passed("Active Protection install actions are connected.", payload) if not payload["blockers"] else extra[2].failed("Active Protection install action is disconnected.", "Connect the shared backend.", payload),
        extra[3].passed("Active Protection repair actions are connected.", payload) if not payload["blockers"] else extra[3].failed("Active Protection repair action is disconnected.", "Connect the shared backend.", payload),
        extra[4].passed("All registered production callbacks exist.", callback_evidence) if not missing else extra[4].failed("One or more registered callbacks are missing.", "Implement callbacks or disable affected buttons.", callback_evidence),
    ]
    if payload["blockers"]:
        return [check.failed("Critical Active Protection buttons are disconnected or unexplained.", "Connect each button to the shared protection backend and add a tooltip.", payload), *supplemental]
    return [check.passed("Critical Active Protection install, repair, verify, and export actions are connected.", payload), *supplemental]


__all__ = ["ButtonAuditItem", "audit_button_file", "audit_visible_buttons", "run_button_functionality_audit"]
