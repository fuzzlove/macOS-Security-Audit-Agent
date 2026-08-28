from __future__ import annotations

import ast
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger(__name__)

EXPECTED_CALLBACKS = {
    "AntiRansomwarePanel": ("install_protection", "view_install_plan", "repair_protection", "verify_protection", "refresh_protection_status", "open_protection_diagnostics"),
    "MainWindow": ("install_active_protection_from_ui", "repair_active_protection_from_ui", "verify_active_protection_from_ui", "export_active_protection_diagnostics"),
    "OperationalHealthPanel": ("install_active_protection_requested", "repair_active_protection_requested", "verify_active_protection_requested", "export_protection_diagnostics_requested"),
}


@dataclass(frozen=True)
class CallbackValidation:
    owner: str
    callback: str
    exists: bool
    event: str = "APP_BUTTON_CALLBACK_MISSING"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def connect_or_disable(button: Any, owner: Any, callback_name: str) -> bool:
    callback = getattr(owner, callback_name, None)
    if callable(callback):
        button.clicked.connect(callback)
        return True
    button.setEnabled(False)
    button.setToolTip("Action unavailable: callback not implemented.")
    LOGGER.error(json.dumps({"event": "APP_BUTTON_CALLBACK_MISSING", "owner": type(owner).__name__, "callback": callback_name}, sort_keys=True))
    return False


def validate_callback_source(root: Path | None = None) -> list[CallbackValidation]:
    root = Path(root or Path.cwd())
    files = {
        "AntiRansomwarePanel": root / "mac_audit_agent/ui/anti_ransomware_panel.py",
        "MainWindow": root / "mac_audit_agent/ui/main_window.py",
        "OperationalHealthPanel": root / "mac_audit_agent/ui/operational_health_panel.py",
    }
    results: list[CallbackValidation] = []
    for owner, callbacks in EXPECTED_CALLBACKS.items():
        methods: set[str] = set()
        try:
            tree = ast.parse(files[owner].read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == owner:
                    methods = {item.name for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    methods.update(target.id for item in node.body if isinstance(item, ast.Assign) for target in item.targets if isinstance(target, ast.Name))
                    methods.update(item.target.id for item in node.body if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name))
        except (OSError, SyntaxError):
            methods = set()
        for callback in callbacks:
            results.append(CallbackValidation(owner, callback, callback in methods))
    return results


__all__ = ["CallbackValidation", "EXPECTED_CALLBACKS", "connect_or_disable", "validate_callback_source"]
