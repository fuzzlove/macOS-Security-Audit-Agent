from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
PYTHON39 = Path("/Library/Developer/CommandLineTools/usr/bin/python3")


def _report_and_text() -> dict:
    code = "from mac_audit_agent.runtime.doctor import build_doctor_report,format_doctor_report; import json; r=build_doctor_report(); print(json.dumps({'report':r,'text':format_doctor_report(r)}))"
    result = subprocess.run([str(PYTHON39), "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.splitlines()[-1])


def test_python39_doctor_is_calm_and_tiered() -> None:
    payload = _report_and_text()
    report, text = payload["report"], payload["text"]
    assert report["result"] == "DOCTOR_ONLY_OK"
    assert report["python"]["runtime_tier"] == "deprecated_doctor_only"
    assert report["python"]["gui_runtime_allowed"] is False
    assert report["python"]["protection_install_allowed"] is False
    assert "Runtime tier: Deprecated doctor-only" in text
    assert "Supported: True" not in text


def test_python39_topology_and_recommendations_are_policy_accurate() -> None:
    payload = _report_and_text()
    report, text = payload["report"], payload["text"]
    assert report["runtime_topology"]["actual_installed_monitor_mode"] == "skipped_by_policy"
    assert report["runtime_topology"]["aligned"] is None
    assert "legacy doctor" not in text.lower()
    assert "python3.12 -m venv .venv" in text
    assert str(PYTHON39) + " -m pip install" not in text
