from mac_audit_agent.runtime.startup_error_classifier import classify_startup_error


def test_qt_appkit_crash_maps_to_guiqt001() -> None:
    result = classify_startup_error(kind="qapplication_crash", details="SIGABRT libqcocoa AppKit HIServices")
    assert result.error_code == "GUIQT001"
    assert result.category == "qt_appkit_startup_crash_risk"


def test_missing_pyside_maps_to_dependency_error() -> None:
    assert classify_startup_error(kind="missing_dependency", details="PySide6").error_code == "DEP003"


def test_stdlib_symbol_and_root_have_distinct_codes() -> None:
    assert classify_startup_error(kind="stdlib_symbol", details="enum.StrEnum").error_code == "PYCOMPAT001"
    assert classify_startup_error(kind="root_gui").error_code == "GUIROOT001"
