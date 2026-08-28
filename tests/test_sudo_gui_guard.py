from __future__ import annotations

import sys

import launcher
from mac_audit_agent.runtime import macos_gui_preflight as preflight


def _root_preflight(monkeypatch):
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)
    monkeypatch.setattr(preflight, "_process_name", lambda pid: "sudo")
    monkeypatch.setattr(preflight, "_display_session_available", lambda: True)
    monkeypatch.setattr(preflight, "run_qt_import_probe", lambda: (_ for _ in ()).throw(AssertionError("Qt probe must not run as root")))
    monkeypatch.setattr(preflight, "matching_crash_marker", lambda **kwargs: None)
    return preflight.run_macos_gui_preflight()


def test_root_gui_is_blocked_before_qt_probe(monkeypatch) -> None:
    before = {name for name in sys.modules if name.startswith("PySide6")}
    result = _root_preflight(monkeypatch)
    after = {name for name in sys.modules if name.startswith("PySide6")}
    assert result.allowed is False
    assert result.failure_code == "GUI_ROOT_NOT_ALLOWED"
    assert result.probe["skipped"] is True
    assert after == before


def test_guiroot001_guidance_is_complete(monkeypatch) -> None:
    result = _root_preflight(monkeypatch)
    message = preflight.format_preflight_block(result)
    assert "GUIROOT001" in message
    assert "Do not start the MSAA GUI with sudo" in message
    assert "--install-protection" in message
    assert "python3.12 launcher.py" in message
    assert "python3.12 -m mac_audit_agent --doctor" in message
    assert "python3.14 launcher.py" not in message


def test_root_doctor_is_allowed_without_gui_preflight(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.runtime.doctor.doctor_main", lambda **_kwargs: 17)
    monkeypatch.setattr(preflight, "run_macos_gui_preflight", lambda **kwargs: (_ for _ in ()).throw(AssertionError("GUI preflight must not run")))
    assert launcher.main(["--doctor"]) == 17


def test_root_install_routes_to_headless_backend(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("mac_audit_agent.protection.__main__.main", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(launcher, "_print_install_handoff", lambda: calls.append("handoff"))
    assert launcher.main(["--install-protection"]) == 0
    assert calls[0][0] == "install"
    assert "--with-system-daemon" in calls[0]
    assert calls[1] == "handoff"


def test_root_repair_routes_to_headless_backend(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("mac_audit_agent.protection.__main__.main", lambda argv: calls.append(argv) or 1)
    assert launcher.main(["--repair-protection"]) == 1
    assert calls[0][0] == "repair"
    assert "--repair-system-daemon" in calls[0]


def test_normal_user_is_not_blocked_by_root_guard(monkeypatch) -> None:
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(preflight, "_python_version_tuple", lambda: (3, 12, 9))
    monkeypatch.setattr(preflight, "_process_name", lambda pid: "zsh")
    monkeypatch.setattr(preflight, "_display_session_available", lambda: True)
    monkeypatch.setattr(preflight.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(preflight, "_package_version", lambda name: "6.11")
    monkeypatch.setattr(preflight, "run_qt_import_probe", lambda: {"safe": True, "qt_version": "6.11"})
    monkeypatch.setattr(preflight, "matching_crash_marker", lambda **kwargs: None)
    monkeypatch.setenv("TERM_PROGRAM", "Apple_Terminal")
    result = preflight.run_macos_gui_preflight()
    assert result.failure_code != "GUI_ROOT_NOT_ALLOWED"


def test_python314_gui_is_blocked_before_qt_probe(monkeypatch) -> None:
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(preflight, "_python_version_tuple", lambda: (3, 14, 6))
    monkeypatch.setattr(preflight, "_process_name", lambda pid: "zsh")
    monkeypatch.setattr(preflight, "_display_session_available", lambda: True)
    monkeypatch.setattr(preflight.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(preflight, "_package_version", lambda name: "6.11")
    monkeypatch.setattr(preflight, "run_qt_import_probe", lambda: (_ for _ in ()).throw(AssertionError("Qt probe must not run on Python 3.14")))
    monkeypatch.setattr(preflight, "matching_crash_marker", lambda **kwargs: None)
    result = preflight.run_macos_gui_preflight()
    assert result.failure_code == "GUI_PYTHON_VERSION_UNVALIDATED"
    assert result.probe["skipped"] is True
