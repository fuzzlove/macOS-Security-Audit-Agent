from __future__ import annotations

from mac_audit_agent.runtime.macos_gui_preflight import MacOSGuiPreflightResult
from mac_audit_agent.runtime.qapplication_guard import ControlledStartupBlock, assert_qapplication_allowed
from pathlib import Path


def _result(**updates):
    values = dict(
        allowed=True, failure_code="", reason="safe", python_executable="/python", python_version="3.12.0",
        macos_version="15.0", architecture="arm64", parent_process="zsh", responsible_process="Terminal",
        is_terminal_launch=True, is_app_bundle_launch=False, is_source_checkout=True, is_root=False,
        display_session_available=True, launchservices_safe=True, qt_available=True, pyside_available=True,
        qt_version="6.11", pyside_version="6.11", launch_mode="terminal_direct_safe",
        recommended_action="start", recommended_commands=(), probe={"safe": True},
    )
    values.update(updates)
    return MacOSGuiPreflightResult(**values)


def test_qapplication_blocked_when_preflight_fails() -> None:
    try:
        assert_qapplication_allowed(_result(allowed=False, failure_code="GUIQT001", reason="unsafe"))
    except ControlledStartupBlock as exc:
        assert exc.code == "GUIQT001"
    else:
        raise AssertionError("unsafe QApplication context was allowed")


def test_prior_crash_marker_blocks_retry(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.runtime.qapplication_guard.matching_crash_marker", lambda **kwargs: {"crash_signature": "SIGABRT"})
    try:
        assert_qapplication_allowed(_result())
    except ControlledStartupBlock as exc:
        assert exc.code == "GUIQT001"
    else:
        raise AssertionError("matching crash marker was ignored")


def test_all_production_qapplication_creation_sites_reference_guard() -> None:
    package = Path(__file__).resolve().parents[1] / "mac_audit_agent"
    unguarded: list[str] = []
    for path in package.rglob("*.py"):
        if "tests" in path.parts or path.name == "qt_smoke_probe.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "QApplication(" in source and "assert_qapplication_allowed" not in source:
            unguarded.append(str(path.relative_to(package.parent)))
    assert unguarded == []
