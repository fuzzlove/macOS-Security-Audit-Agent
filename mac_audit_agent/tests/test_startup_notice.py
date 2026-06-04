import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog

from mac_audit_agent import app as app_module
from mac_audit_agent.ui.startup_notice import (
    STARTUP_NOTICE_TEXT,
    STARTUP_NOTICE_VERSION,
    preview_startup_notice,
    record_startup_notice_preview,
    startup_notice_has_been_previewed,
)


def test_notice_text_is_explicitly_non_binding_and_explains_operational_limits() -> None:
    assert "not a contract" in STARTUP_NOTICE_TEXT
    assert "not acceptance of a binding agreement" in STARTUP_NOTICE_TEXT
    assert "not proof of compromise" in STARTUP_NOTICE_TEXT
    assert "Background monitoring is optional" in STARTUP_NOTICE_TEXT
    assert "separately confirmed" in STARTUP_NOTICE_TEXT
    assert "explicitly authorized" in STARTUP_NOTICE_TEXT


def test_recorded_notice_preview_is_recognized(tmp_path: Path) -> None:
    state_path = tmp_path / "state" / "startup_notice.json"
    assert startup_notice_has_been_previewed(state_path) is False
    record_startup_notice_preview(state_path)
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["notice_version"] == STARTUP_NOTICE_VERSION
    assert payload["previewed"] is True
    assert payload["binding_agreement"] is False
    assert startup_notice_has_been_previewed(state_path) is True


def test_outdated_or_invalid_notice_state_is_not_recognized(tmp_path: Path) -> None:
    state_path = tmp_path / "startup_notice.json"
    state_path.write_text("{invalid", encoding="utf-8")
    assert startup_notice_has_been_previewed(state_path) is False
    state_path.write_text(json.dumps({"notice_version": "older", "previewed": True}), encoding="utf-8")
    assert startup_notice_has_been_previewed(state_path) is False


def test_declining_notice_does_not_record_preview(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    state_path = tmp_path / "startup_notice.json"
    monkeypatch.setattr("mac_audit_agent.ui.startup_notice.StartupNoticeDialog.exec", lambda self: QDialog.Rejected)
    assert preview_startup_notice(state_path=state_path) is False
    assert state_path.exists() is False
    app.processEvents()


def test_accepting_notice_records_preview_and_skips_future_dialog(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    state_path = tmp_path / "startup_notice.json"
    calls = []

    def accept_dialog(self) -> int:
        calls.append("shown")
        return QDialog.Accepted

    monkeypatch.setattr("mac_audit_agent.ui.startup_notice.StartupNoticeDialog.exec", accept_dialog)
    assert preview_startup_notice(state_path=state_path) is True
    assert preview_startup_notice(state_path=state_path) is True
    assert calls == ["shown"]
    app.processEvents()


def test_accepting_notice_still_continues_when_preview_cannot_be_recorded(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    state_path = tmp_path / "startup_notice.json"

    def fail_record(path: Path) -> None:
        raise OSError("read-only state directory")

    monkeypatch.setattr("mac_audit_agent.ui.startup_notice.StartupNoticeDialog.exec", lambda self: QDialog.Accepted)
    monkeypatch.setattr("mac_audit_agent.ui.startup_notice.record_startup_notice_preview", fail_record)
    assert preview_startup_notice(state_path=state_path) is True
    assert state_path.exists() is False
    app.processEvents()


def test_app_exit_before_main_window_when_notice_is_declined(monkeypatch) -> None:
    windows = []
    monkeypatch.setattr(app_module, "QApplication", lambda argv: object())
    monkeypatch.setattr(app_module, "preview_startup_notice", lambda: False)
    monkeypatch.setattr(app_module, "MainWindow", lambda db_path: windows.append(db_path))
    assert app_module.main() == 0
    assert windows == []


def test_app_opens_main_window_after_notice_is_previewed(monkeypatch) -> None:
    calls = []

    class FakeApplication:
        def __init__(self, argv) -> None:
            calls.append("application")

        def exec(self) -> int:
            calls.append("event-loop")
            return 17

    class FakeWindow:
        def __init__(self, db_path: Path) -> None:
            calls.append("window")

        def show(self) -> None:
            calls.append("show")

    monkeypatch.setattr(app_module, "QApplication", FakeApplication)
    monkeypatch.setattr(app_module, "preview_startup_notice", lambda: calls.append("notice") or True)
    monkeypatch.setattr(app_module, "MainWindow", FakeWindow)
    assert app_module.main() == 17
    assert calls == ["application", "notice", "window", "show", "event-loop"]
