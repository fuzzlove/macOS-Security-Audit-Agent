from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _probe(command: list[str], cwd: Path | None = None) -> dict[str, object]:
    script = """
import json, subprocess, sys
cmd = %r
result = subprocess.run(cmd, text=True, capture_output=True, check=False)
print(json.dumps({
  "returncode": result.returncode,
  "stdout": result.stdout,
  "stderr": result.stderr,
  "gui_modules": sorted(m for m in sys.modules if m.split(".", 1)[0] in {"PySide6", "PyQt6", "PyQt5", "AppKit", "Cocoa"}),
}))
""" % command
    completed = subprocess.run([sys.executable, "-c", script], cwd=cwd, text=True, capture_output=True, check=False, timeout=30)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_integrity_import_does_not_load_gui_modules() -> None:
    script = """
import importlib, json, sys
importlib.import_module("mac_audit_agent.integrity")
print(json.dumps(sorted(m for m in sys.modules if m.split(".", 1)[0] in {"PySide6", "PyQt6", "PyQt5", "AppKit", "Cocoa"})))
"""
    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_integrity_doctor_command_is_headless(tmp_path: Path) -> None:
    result = _probe([sys.executable, "-m", "mac_audit_agent.integrity", "doctor", "--root", str(tmp_path), "--policy", "dev", "--json"])
    assert result["gui_modules"] == []
    assert "QApplication" not in str(result["stderr"])


def test_integrity_verify_command_is_headless(tmp_path: Path) -> None:
    result = _probe([sys.executable, "-m", "mac_audit_agent.integrity", "verify", "--root", str(tmp_path), "--policy", "dev", "--strict"])
    assert result["gui_modules"] == []
    assert "QApplication" not in str(result["stderr"])


def test_preflight_command_is_headless(tmp_path: Path) -> None:
    result = _probe([sys.executable, "-m", "mac_audit_agent.integrity", "preflight", "--root", str(tmp_path), "--policy", "dev", "--strict"])
    assert result["gui_modules"] == []
    assert "QApplication" not in str(result["stderr"])


def test_parent_qt_import_does_not_contaminate_isolated_integrity_check() -> None:
    __import__("PySide6")
    from mac_audit_agent.integrity.headless_sentinel import isolated_integrity_import_check

    result = isolated_integrity_import_check()
    assert result.headless_safe is True
    assert result.imported_gui_modules == []
