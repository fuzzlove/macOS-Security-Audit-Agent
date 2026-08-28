from __future__ import annotations

import json
import subprocess
import sys


def _probe(code: str) -> dict:
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30, check=False)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert result.returncode in {0, 1, 2}
    return payload


def test_doctor_does_not_import_qt() -> None:
    payload = _probe("from mac_audit_agent.runtime.doctor import build_doctor_report; import sys,json; build_doctor_report(); print(json.dumps({'qt': any(n.startswith('PySide6') for n in sys.modules)}))")
    assert payload["qt"] is False


def test_protection_status_does_not_import_qt() -> None:
    payload = _probe("from mac_audit_agent.protection.status import resolve_active_protection_status; import sys,json; resolve_active_protection_status(); print(json.dumps({'qt': any(n.startswith('PySide6') for n in sys.modules)}))")
    assert payload["qt"] is False
