from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("msaa_stage0_launcher", ROOT / "launcher.py")
launcher = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(launcher)


def test_gui_selector_prefers_first_supported_candidate(monkeypatch) -> None:
    monkeypatch.setattr(launcher, "_candidate_paths", lambda mode, launcher_path=None: ["/python3.13", "/python3.12", "/python3.9"])
    versions = {"/python3.13": (3, 13, 4), "/python3.12": (3, 12, 9), "/python3.9": (3, 9, 6)}
    monkeypatch.setattr(launcher, "_probe_python", lambda path, mode: {"executable": path, "accepted": launcher._version_allowed(versions[path], mode), "reason": "probe", "version": list(versions[path])})
    result = launcher.select_python_for_mode("gui")
    assert result["selected"] == "/python3.13"
    assert not launcher._version_allowed((3, 9, 6), "gui")
    assert not launcher._version_allowed((3, 14, 0), "gui")


def test_no_candidate_guidance_uses_venv_not_clt_pip() -> None:
    text = launcher._setup_guidance({"current": "/Library/Developer/CommandLineTools/usr/bin/python3"})
    assert "python3.13 -m venv .venv" in text
    assert "pip install -e" in text
    assert "bootstrap/doctor only" in text
    assert "/Library/Developer/CommandLineTools/usr/bin/python3 -m pip" not in text


def test_doctor_does_not_reexec(monkeypatch) -> None:
    args = launcher._parser().parse_args(["--doctor"])
    monkeypatch.setattr(launcher, "select_python_for_mode", lambda mode: {"mode": mode, "current": sys.executable, "current_suitable": True, "selected": sys.executable, "candidates": []})
    assert launcher._bootstrap_runtime(args, ["--doctor"]) is None


def test_frozen_launcher_never_reexecutes_external_python(monkeypatch) -> None:
    args = launcher._parser().parse_args(["--debug-startup"])
    monkeypatch.setattr(launcher.sys, "frozen", True, raising=False)

    def unexpected_selection(_mode):
        raise AssertionError("a frozen application must use its embedded runtime")

    monkeypatch.setattr(launcher, "select_python_for_mode", unexpected_selection)

    assert launcher._bootstrap_runtime(args, ["--debug-startup"]) is None


def test_no_auto_python_disables_reexec(monkeypatch, capsys) -> None:
    args = launcher._parser().parse_args(["--no-auto-python"])
    monkeypatch.setattr(launcher, "select_python_for_mode", lambda mode: {"mode": mode, "current": "/python3.9", "current_suitable": False, "selected": "/python3.12", "candidates": []})
    assert launcher._bootstrap_runtime(args, ["--no-auto-python"]) == 2
    error=capsys.readouterr().err
    assert "GUI001_UNSUPPORTED_PYTHON" in error
    assert "python3.12 launcher.py" in error


def test_reexec_preserves_args_and_sets_loop_guard(monkeypatch) -> None:
    args = launcher._parser().parse_args(["--safe-gui-check"])
    monkeypatch.setattr(launcher, "select_python_for_mode", lambda mode: {"mode": mode, "current": "/python3.9", "current_suitable": False, "selected": "/python3.12", "candidates": []})
    monkeypatch.delenv("MSAA_BOOTSTRAP_DEPTH", raising=False)
    captured = {}
    def fake_exec(path, argv):
        captured.update(path=path, argv=argv)
        raise RuntimeError("exec captured")
    monkeypatch.setattr(launcher.os, "execv", fake_exec)
    try:
        launcher._bootstrap_runtime(args, ["--safe-gui-check"])
    except RuntimeError:
        pass
    assert captured["path"] == "/python3.12"
    assert captured["argv"][-1] == "--safe-gui-check"
    assert os.environ["MSAA_BOOTSTRAP_DEPTH"] == "1"


def test_depth_limit_prevents_loop(monkeypatch, capsys) -> None:
    args = launcher._parser().parse_args([])
    monkeypatch.setattr(launcher, "select_python_for_mode", lambda mode: {"mode": mode, "current": "/python3.9", "current_suitable": False, "selected": "/python3.12", "candidates": []})
    monkeypatch.setenv("MSAA_BOOTSTRAP_DEPTH", "2")
    assert launcher._bootstrap_runtime(args, []) == 2
    assert "depth limit" in capsys.readouterr().err


def test_print_selection_is_headless_and_has_reasons() -> None:
    result = subprocess.run([sys.executable, str(ROOT / "launcher.py"), "--print-python-selection"], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["selected"]
    assert all("reason" in item for item in payload["candidates"])
    assert "PySide6" not in result.stdout + result.stderr


def test_launcher_has_no_top_level_project_or_gui_import() -> None:
    source = (ROOT / "launcher.py").read_text(encoding="utf-8")
    prefix = source.split("def _parser", 1)[0]
    assert "mac_audit_agent" not in prefix
    assert "PySide6" not in prefix
