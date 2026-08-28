from __future__ import annotations

import json
import subprocess
import sys

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


HEADLESS_IMPORT_MODULES = [
    "mac_audit_agent.integrity",
    "mac_audit_agent.quality.pre_uat_audit",
    "mac_audit_agent.evidence",
    "mac_audit_agent.exporters",
]


def run_runtime_headless_audit(context: AuditContext) -> list[FunctionalCheck]:
    check = FunctionalCheck("runtime.no_qt_in_headless_paths", "Runtime", "no Qt in headless paths", "Headless integrity, Pre-UAT, reports, and evidence imports do not load Qt/AppKit.", "blocker", "runtime")
    script = """
import importlib, json, sys
modules = %r
results = {}
for name in modules:
    before = set(sys.modules)
    importlib.import_module(name)
    loaded = sorted(m for m in sys.modules if m.split('.', 1)[0] in {'PySide6', 'PyQt6', 'PyQt5', 'AppKit', 'Cocoa'})
    qapps = sorted(m for m in sys.modules if 'QApplication' in m)
    results[name] = {'loaded_gui_modules': loaded, 'qapplication_modules': qapps}
print(json.dumps(results, sort_keys=True))
""" % (HEADLESS_IMPORT_MODULES,)
    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False, timeout=20)
    evidence = {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "modules": HEADLESS_IMPORT_MODULES,
    }
    if result.returncode != 0:
        return [check.failed("Headless import probe failed.", "Fix import-time side effects in headless modules.", evidence)]
    try:
        payload = json.loads(result.stdout)
    except Exception as exc:
        return [check.failed("Headless import probe did not return JSON.", "Fix runtime headless probe output.", evidence | {"exception": type(exc).__name__})]
    offenders = {name: data for name, data in payload.items() if data.get("loaded_gui_modules") or data.get("qapplication_modules")}
    if offenders:
        return [check.failed("Qt/AppKit modules loaded in a headless import path.", "Move GUI imports behind explicit GUI entrypoints or --ui-interactive guards.", evidence | {"offenders": offenders})]
    return [check.passed("Headless imports did not load Qt/AppKit or QApplication.", evidence | {"status": "verified", "results": payload})]


__all__ = ["run_runtime_headless_audit"]
