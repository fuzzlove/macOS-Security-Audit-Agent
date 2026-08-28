from __future__ import annotations

from mac_audit_agent.runtime.detector import detect_python_runtime
from mac_audit_agent.runtime.python_selector import select_best_python_for_mode
from mac_audit_agent.runtime.support_matrix import RuntimeTier, classify_runtime


def test_support_tiers_are_explicit(monkeypatch) -> None:
    monkeypatch.delenv("MSAA_ALLOW_EXPERIMENTAL_PY314_GUI", raising=False)
    assert classify_runtime((3, 12, 0)).tier is RuntimeTier.FULL
    assert classify_runtime((3, 14, 0)).tier is RuntimeTier.HEADLESS
    assert not classify_runtime((3, 14, 0)).gui_allowed
    assert classify_runtime((3, 9, 0)).tier is RuntimeTier.DOCTOR
    assert classify_runtime((3, 8, 0)).tier is RuntimeTier.DOCTOR


def test_runtime_detector_has_required_stdlib_and_origin_fields() -> None:
    runtime = detect_python_runtime()
    assert runtime.executable
    assert runtime.version_tuple >= (3, 9)
    assert runtime.has_ssl and runtime.has_sqlite3
    assert runtime.runtime_tier
    assert isinstance(runtime.sys_path, tuple)


def test_gui_selector_avoids_unvalidated_python_314(monkeypatch) -> None:
    monkeypatch.delenv("MSAA_ALLOW_EXPERIMENTAL_PY314_GUI", raising=False)
    selection = select_best_python_for_mode("gui")
    if selection.suitable:
        assert not selection.version.startswith("3.14")


def test_notifier_selector_is_gui_capable() -> None:
    selection = select_best_python_for_mode("notifier")
    assert selection.suitable
    assert tuple(map(int, selection.version.split(".")[:2])) <= (3, 13)
