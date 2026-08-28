from __future__ import annotations

from mac_audit_agent.runtime import macos_gui_preflight as preflight


def test_python310_terminal_source_checkout_is_blocked(monkeypatch) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(preflight, "_python_version_tuple", lambda: (3, 10, 20))
    monkeypatch.setattr(preflight, "_process_name", lambda pid: "/bin/zsh")
    monkeypatch.setattr(preflight, "_display_session_available", lambda: True)
    monkeypatch.setattr(preflight, "_package_version", lambda name: "6.11.1")
    monkeypatch.setattr(preflight.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(preflight, "run_qt_import_probe", lambda: {"safe": True, "qt_version": "6.11.1"})
    monkeypatch.setattr(preflight, "matching_crash_marker", lambda **kwargs: None)
    monkeypatch.setenv("TERM_PROGRAM", "Apple_Terminal")

    result = preflight.run_macos_gui_preflight()

    assert result.allowed is False
    assert result.failure_code == "GUI_UNSAFE_TERMINAL_QT_COCOA"
    assert "supported generally" in result.reason


def test_default_qt_probe_command_does_not_request_qapplication(monkeypatch) -> None:
    captured: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = '{"safe": true, "qt_version": "6.11"}\n'
        stderr = ""

    monkeypatch.setattr(preflight.subprocess, "run", lambda command, **kwargs: captured.append(command) or Result())
    assert preflight.run_qt_import_probe()["safe"] is True
    assert "--allow-qapplication-probe" not in captured[0]
