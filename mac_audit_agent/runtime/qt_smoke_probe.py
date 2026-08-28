"""Isolated Qt import probe. Normal use never creates QApplication."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from typing import Any


def run_probe(*, allow_qapplication_probe: bool = False) -> dict[str, Any]:
    levels: list[dict[str, Any]] = []
    payload: dict[str, Any] = {
        "safe": False,
        "qapplication_attempted": False,
        "levels": levels,
        "python_executable": sys.executable,
        "python_version": ".".join(str(item) for item in sys.version_info[:3]),
        "pyside_version": "unknown",
        "qt_version": "unknown",
    }
    if allow_qapplication_probe:
        from mac_audit_agent.runtime.gui_preflight import evaluate_gui_preflight
        preflight=evaluate_gui_preflight()
        payload["preflight"]=preflight.to_dict()
        if not preflight.allowed:
            payload["failure_code"]=preflight.failure_code
            payload["failure_message"]=preflight.message
            return payload
    for module_name in ("PySide6", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"):
        try:
            module = importlib.import_module(module_name)
        except BaseException as exc:
            levels.append({"module": module_name, "ok": False, "error": "%s: %s" % (type(exc).__name__, exc)})
            payload["failure_module"] = module_name
            return payload
        levels.append({"module": module_name, "ok": True})
        if module_name == "PySide6":
            payload["pyside_version"] = str(getattr(module, "__version__", "unknown"))
        elif module_name == "PySide6.QtCore":
            payload["qt_version"] = str(module.qVersion())
    payload["safe"] = True
    if allow_qapplication_probe:
        payload["qapplication_attempted"] = True
        try:
            widgets = sys.modules["PySide6.QtWidgets"]
            app = widgets.QApplication.instance() or widgets.QApplication(["msaa-qt-smoke-probe"])
            app.processEvents()
            payload["qapplication_created"] = True
        except BaseException as exc:
            payload["safe"] = False
            payload["qapplication_created"] = False
            payload["qapplication_error"] = "%s: %s" % (type(exc).__name__, exc)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe PySide6 imports without initializing a GUI by default.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--allow-qapplication-probe", action="store_true")
    args = parser.parse_args(argv)
    result = run_probe(allow_qapplication_probe=args.allow_qapplication_probe)
    output = json.dumps(result, sort_keys=True)
    print(output if args.json else "MSAA Qt smoke probe\n" + output)
    return 0 if result["safe"] else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_probe"]
