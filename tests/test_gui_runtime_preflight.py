from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mac_audit_agent.runtime.gui_preflight import AquaState, GuiFailureCode, evaluate_gui_preflight, run_isolated_cocoa_probe

ROOT=Path(__file__).resolve().parents[1]


def clean_automation(monkeypatch)->None:
    for name in ("CI","CODEX_HOME","MSAA_GUI_AUTOMATION_MODE","MSAA_GUI_TEST_BACKEND","SSH_CONNECTION","SSH_TTY","MSAA_LAUNCH_DOMAIN"):
        monkeypatch.delenv(name,raising=False)


def test_python39_blocked_with_exact_guidance_before_qt(monkeypatch):
    clean_automation(monkeypatch)
    result=evaluate_gui_preflight(version_info=(3,9,6),euid=501,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin")
    assert result.failure_code==GuiFailureCode.UNSUPPORTED_PYTHON.value
    assert "python3.12 launcher.py" in result.message and "--doctor" in result.message
    assert "PySide6.QtGui" not in sys.modules and "PySide6.QtWidgets" not in sys.modules


@pytest.mark.parametrize("version",[(3,10,14),(3,11,9),(3,14,0)])
def test_unvalidated_gui_versions_fail_closed(monkeypatch,version):
    clean_automation(monkeypatch)
    assert evaluate_gui_preflight(version_info=version,euid=501,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin").failure_code=="GUI001_UNSUPPORTED_PYTHON"


def test_supported_runtime_context_matrix(monkeypatch):
    clean_automation(monkeypatch)
    assert evaluate_gui_preflight(version_info=(3,12,9),euid=0,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin").failure_code=="GUI003_ROOT_GUI_FORBIDDEN"
    assert evaluate_gui_preflight(version_info=(3,12,9),euid=501,parent_process="launchd",aqua_state=AquaState.UNAVAILABLE,platform_name="darwin").failure_code=="GUI004_LAUNCHDAEMON_GUI_FORBIDDEN"
    assert evaluate_gui_preflight(version_info=(3,13,2),euid=501,parent_process="zsh",aqua_state=AquaState.UNAVAILABLE,platform_name="darwin").failure_code=="GUI002_NO_AQUA_SESSION"


def test_missing_qt_shows_selected_interpreter_and_venv_recovery(monkeypatch):
    clean_automation(monkeypatch)
    monkeypatch.setattr("mac_audit_agent.runtime.gui_preflight._dependency_diagnostics",lambda:("not installed","not installed","",False))
    result=evaluate_gui_preflight(version_info=(3,13,2),euid=501,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin")
    assert result.failure_code=="GUI006_QT_IMPORT_FAILED"
    assert result.python_executable in result.message
    assert "-m venv .venv" in result.message
    assert 'pip install ".[gui]"' in result.message


def test_preflight_preserves_virtualenv_interpreter_path(monkeypatch, tmp_path):
    clean_automation(monkeypatch)
    interpreter = tmp_path / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(sys.executable)
    monkeypatch.setattr(sys, "executable", str(interpreter))
    monkeypatch.setattr("mac_audit_agent.runtime.gui_preflight._dependency_diagnostics",lambda:("not installed","not installed","",False))

    result=evaluate_gui_preflight(version_info=(3,13,2),euid=501,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin")

    assert result.python_executable == str(interpreter)
    assert str(interpreter) in result.message


def test_codex_requires_explicit_backend_and_offscreen_never_uses_cocoa(monkeypatch):
    clean_automation(monkeypatch)
    blocked=evaluate_gui_preflight(version_info=(3,12,9),euid=501,parent_process="codex",aqua_state=AquaState.AVAILABLE,platform_name="darwin")
    assert blocked.failure_code=="GUI005_UNSAFE_PARENT_PROCESS"
    monkeypatch.setenv("MSAA_GUI_TEST_BACKEND","offscreen")
    allowed=evaluate_gui_preflight(version_info=(3,12,9),euid=501,parent_process="codex",aqua_state=AquaState.UNAVAILABLE,platform_name="darwin")
    assert allowed.allowed and os.environ["QT_QPA_PLATFORM"]=="offscreen" and allowed.launch_mode=="automation_offscreen"


def test_wrong_thread_is_rejected(monkeypatch):
    clean_automation(monkeypatch);results=[]
    thread=threading.Thread(target=lambda:results.append(evaluate_gui_preflight(version_info=(3,12,9),euid=501,parent_process="zsh",aqua_state=AquaState.AVAILABLE,platform_name="darwin")))
    thread.start();thread.join();assert results[0].failure_code=="GUI009_WRONG_THREAD"


def test_launcher_json_preflight_on_current_runtime_never_imports_qt():
    code="import json,sys,launcher; rc=launcher.main(['--gui-preflight-json']); print(json.dumps({'rc':rc,'qtgui':'PySide6.QtGui' in sys.modules,'qtwidgets':'PySide6.QtWidgets' in sys.modules,'main_window':'mac_audit_agent.ui.main_window' in sys.modules}))"
    result=subprocess.run([sys.executable,"-c",code],cwd=ROOT,capture_output=True,text=True,timeout=10,check=False)
    payload=json.loads(result.stdout.strip().splitlines()[-1]);assert not payload["qtgui"] and not payload["qtwidgets"] and not payload["main_window"]
    if sys.version_info[:2]==(3,9):assert payload["rc"]==2 and "GUI001_UNSUPPORTED_PYTHON" in result.stdout


def test_doctor_route_does_not_import_qt_or_main_window():
    code="import json,sys,launcher; rc=launcher.main(['--doctor','--json']); print(json.dumps({'sentinel':True,'rc':rc,'qtgui':'PySide6.QtGui' in sys.modules,'qtwidgets':'PySide6.QtWidgets' in sys.modules,'main_window':'mac_audit_agent.ui.main_window' in sys.modules}))"
    result=subprocess.run([sys.executable,"-c",code],cwd=ROOT,capture_output=True,text=True,timeout=20,check=False)
    payload=json.loads(result.stdout.strip().splitlines()[-1]);assert payload["sentinel"] and not payload["qtgui"] and not payload["qtwidgets"] and not payload["main_window"]


def test_direct_app_import_under_unsupported_runtime_stops_before_qt():
    if sys.version_info[:2] in {(3,12),(3,13)}:pytest.skip("Requires an unsupported interpreter")
    code="import sys\ntry:\n import mac_audit_agent.app\nexcept Exception as exc:\n print(type(exc).__name__,getattr(exc,'code',''))\nprint('QTGUI', 'PySide6.QtGui' in sys.modules, 'QTWIDGETS', 'PySide6.QtWidgets' in sys.modules)"
    result=subprocess.run([sys.executable,"-c",code],cwd=ROOT,capture_output=True,text=True,timeout=10,check=False)
    assert "GUI001_UNSUPPORTED_PYTHON" in result.stdout and "QTGUI False QTWIDGETS False" in result.stdout


def test_isolated_probe_converts_sigabrt_without_risking_parent():
    class Completed:
        returncode=-6;stdout="";stderr="libqcocoa abort"
    result=run_isolated_cocoa_probe(runner=lambda *_args,**_kwargs:Completed())
    assert result["failure_code"]=="GUI007_COCOA_PROBE_FAILED" and result["error_code"]=="PROBE_SIGABRT"


def test_isolated_probe_timeout_and_malformed_output():
    def timeout(*_args,**_kwargs):raise subprocess.TimeoutExpired("probe",1)
    assert run_isolated_cocoa_probe(runner=timeout)["error_code"]=="PROBE_TIMEOUT"
    class Completed:
        returncode=0;stdout="not-json";stderr=""
    assert run_isolated_cocoa_probe(runner=lambda *_args,**_kwargs:Completed())["error_code"]=="PROBE_MALFORMED_OUTPUT"
