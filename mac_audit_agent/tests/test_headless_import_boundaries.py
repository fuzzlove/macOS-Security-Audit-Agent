from __future__ import annotations

import json
import subprocess
import sys

from mac_audit_agent.runtime.execution_context import detect_execution_context
from mac_audit_agent.runtime.gui_import_guard import UnsafeGuiImportError, assert_gui_import_allowed


def _probe_import(module: str) -> dict[str, object]:
    script = """
import importlib, json, sys
importlib.import_module(%r)
print(json.dumps({
    'gui_modules': sorted(m for m in sys.modules if m.split('.', 1)[0] in {'PySide6', 'PyQt6', 'PyQt5', 'AppKit', 'Cocoa'}),
    'qapplication_loaded': any('QApplication' in m for m in sys.modules),
}, sort_keys=True))
""" % module
    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False, timeout=20)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_integrity_imports_no_qt() -> None:
    result = _probe_import("mac_audit_agent.integrity")
    assert result["gui_modules"] == []
    assert result["qapplication_loaded"] is False


def test_pre_uat_imports_no_qt() -> None:
    result = _probe_import("mac_audit_agent.quality.pre_uat_audit")
    assert result["gui_modules"] == []
    assert result["qapplication_loaded"] is False


def test_reports_import_no_qt() -> None:
    result = _probe_import("mac_audit_agent.exporters")
    assert result["gui_modules"] == []
    assert result["qapplication_loaded"] is False


def test_evidence_import_no_qt() -> None:
    result = _probe_import("mac_audit_agent.evidence")
    assert result["gui_modules"] == []
    assert result["qapplication_loaded"] is False


def test_qt_import_guard_blocks_terminal_context() -> None:
    try:
        assert_gui_import_allowed("unit test terminal context")
    except UnsafeGuiImportError as exc:
        assert "Unsafe GUI import blocked" in str(exc)
    else:
        context = detect_execution_context()
        assert context.can_import_gui is True


def test_python314_gui_blocked() -> None:
    context = detect_execution_context()
    if context.python_version.startswith("3.14"):
        assert context.can_create_qapplication is False
