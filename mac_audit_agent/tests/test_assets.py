import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.assets import get_asset_path
from mac_audit_agent.ui.main_window import MainWindow


def test_asset_path_resolves_logo() -> None:
    path = get_asset_path("logo.png")
    assert path.name == "logo.png"
    assert path.exists()


def test_asset_path_resolves_from_pyinstaller_bundle(tmp_path: Path, monkeypatch) -> None:
    bundle_assets = tmp_path / "mac_audit_agent" / "assets"
    bundle_assets.mkdir(parents=True)
    bundled_logo = bundle_assets / "logo.png"
    bundled_logo.write_bytes(b"bundle-logo")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    path = get_asset_path("logo.png")
    assert path == bundled_logo


def test_missing_logo_does_not_crash_ui(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("mac_audit_agent.ui.main_window.get_asset_path", lambda name: tmp_path / name)
    window = MainWindow(tmp_path / "audit.sqlite")
    header_pixmap = window.header_logo_label.pixmap()
    dashboard_pixmap = window.dashboard_logo_label.pixmap()
    assert header_pixmap is None or header_pixmap.isNull()
    assert dashboard_pixmap is None or dashboard_pixmap.isNull()
    window.close()
    app.processEvents()


def test_usage_readme_dialog_opens_when_readme_exists(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    readme_path = tmp_path / "README.md"
    readme_path.write_text("# Mac Audit Agent\n\nUsage details.", encoding="utf-8")
    exec_calls = []

    monkeypatch.setattr("mac_audit_agent.ui.main_window.get_asset_path", lambda name: tmp_path / name)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QDialog.exec", lambda self: exec_calls.append(self.windowTitle()) or 0)
    window = MainWindow(tmp_path / "audit.sqlite")
    monkeypatch.setattr(window, "_usage_readme_path", lambda: readme_path)
    window.show_usage_readme()
    assert exec_calls == ["How to Use macOS Security Audit Agent - Liquidsky Network Security"]
    window.close()
    app.processEvents()


def test_main_window_title_includes_liquidsky_brand(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.windowTitle() == "macOS Security Audit Agent - Liquidsky Network Security"
    window.close()
    app.processEvents()


def test_open_reports_folder_uses_application_support_path(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    reports_dir = tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    calls = []
    messages = []
    monkeypatch.setattr("mac_audit_agent.ui.main_window.get_reports_dir", lambda: reports_dir)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.subprocess.run", lambda args, check=False: calls.append(args))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.information", lambda *args, **kwargs: messages.append(args[2]))
    window.open_reports_folder()
    assert calls == [["open", str(reports_dir)]]
    assert reports_dir.exists()
    assert "Reports folder opened" in messages[0]
    window.close()
    app.processEvents()


def test_usage_readme_path_uses_pyinstaller_bundle(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    bundled_readme = tmp_path / "README.md"
    bundled_readme.write_text("# Bundled README", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window._usage_readme_path() == bundled_readme
    window.close()
    app.processEvents()
