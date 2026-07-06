import os
import sys
import json
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel
from PySide6.QtCore import Qt

from mac_audit_agent.assets import get_asset_path, get_donation_qr_metadata_path, get_donation_qr_path
from mac_audit_agent.branding.support_links import SUPPORT_LINKS
from mac_audit_agent.ui.main_window import MainWindow, STARTUP_STRATEGY_QUOTES, choose_startup_strategy_quote, create_fallback_qr_pixmap, format_startup_strategy_quote


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
    assert exec_calls == ["How to Use macOS Security Audit Agent"]
    window.close()
    app.processEvents()


def test_main_window_title_uses_public_product_name(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.windowTitle() == "macOS Security Audit Agent"
    window.close()
    app.processEvents()


def test_startup_strategy_quote_picker_excludes_previous_quote() -> None:
    previous = format_startup_strategy_quote(STARTUP_STRATEGY_QUOTES[0])

    class FakeRandom:
        def choice(self, values):
            assert previous not in values
            return values[0]

    assert choose_startup_strategy_quote(previous, rng=FakeRandom()) != previous


def test_main_window_shows_new_strategy_quote_each_open(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db_path = tmp_path / "audit.sqlite"
    formatted_quotes = {format_startup_strategy_quote(entry) for entry in STARTUP_STRATEGY_QUOTES}
    first_window = MainWindow(db_path)
    first_quote = first_window.startup_quote
    assert first_window.startup_quote_label.text() == first_quote
    assert first_quote in formatted_quotes
    first_window.close()

    second_window = MainWindow(db_path)
    second_quote = second_window.startup_quote
    assert second_window.startup_quote_label.text() == second_quote
    assert second_quote in formatted_quotes
    assert second_quote != first_quote
    second_window.close()
    app.processEvents()


def test_startup_strategy_quotes_include_requested_theme_sources() -> None:
    texts = [entry["text"] for entry in STARTUP_STRATEGY_QUOTES]
    assert any(entry["source"] == "Sun Tzu" for entry in STARTUP_STRATEGY_QUOTES)
    assert any("Power" in text or "power" in text for text in texts)
    assert any("Influence" in text or "attention" in text for text in texts)
    assert any("Mastery" in text or "Skill" in text or "mastery" in text for text in texts)


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


def test_support_rail_uses_image_and_patreon_link(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    from PySide6.QtGui import QColor, QPixmap

    def fake_support_image(*_args, **_kwargs):
        pixmap = QPixmap(100, 100)
        pixmap.fill(QColor("#FFFFFF"))
        return pixmap

    monkeypatch.setattr("mac_audit_agent.ui.main_window.load_support_image_pixmap", fake_support_image)
    opened_urls = []
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QDesktopServices.openUrl", lambda url: opened_urls.append(url.toString()))
    window = MainWindow(tmp_path / "audit.sqlite")
    assert hasattr(window, "details_panel")
    assert hasattr(window, "support_ad_frame")
    assert hasattr(window, "support_ad_image_label")
    assert hasattr(window, "support_ad_link_label")
    assert hasattr(window, "support_ad_scroll_area")
    assert window.sidebar.item(window.sidebar.count() - 1).text() == "Support the Author"
    assert window.pages.widget(window.pages.count() - 1).findChild(type(window.support_ad_frame), "supportAd") is window.support_ad_frame
    assert window.support_ad_frame.parent() is not window.details_panel
    assert window.support_ad_frame.cursor().shape() == Qt.PointingHandCursor
    pixmap = window.support_ad_image_label.pixmap()
    assert pixmap is not None and not pixmap.isNull()
    assert window.support_ad_image_label.minimumWidth() >= 180
    assert window.support_ad_image_label.minimumHeight() >= 180
    assert window.support_ad_image_label.maximumWidth() >= window.support_ad_image_label.minimumWidth()
    assert window.support_ad_frame.minimumHeight() >= 420
    assert window.support_ad_scroll_area.widgetResizable()
    assert window.support_ad_scroll_area.verticalScrollBarPolicy() == Qt.ScrollBarAsNeeded
    assert f'<a href="{SUPPORT_LINKS["patreon"]}">Patreon</a>' in window.support_ad_link_label.text()
    assert SUPPORT_LINKS["buy_me_a_coffee"] in window.support_ad_link_label.text()
    assert SUPPORT_LINKS["github"] in window.support_ad_link_label.text()
    assert SUPPORT_LINKS["website"] in window.support_ad_link_label.text()
    assert window.support_ad_link_label.wordWrap()
    assert window.support_ad_frame.toolTip().startswith("Open Patreon support page:")

    class FakeEvent:
        def button(self):
            return Qt.LeftButton

        def accept(self):
            return None

    window.support_ad_frame.mousePressEvent(FakeEvent())
    assert opened_urls == [SUPPORT_LINKS["patreon"]]
    window.support_ad_buttons[1].click()
    assert opened_urls[-1] == SUPPORT_LINKS["buy_me_a_coffee"]
    assert not create_fallback_qr_pixmap().isNull()
    window.close()
    app.processEvents()


def test_support_author_navigation_is_final_and_unique(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    titles = [window.sidebar.item(index).text() for index in range(window.sidebar.count())]
    assert titles[-1] == "Support the Author"
    assert titles.count("Support the Author") == 1
    assert window.pages.count() == window.sidebar.count()
    assert window.navigate_to_view("support_author") is True
    assert window.sidebar.currentRow() == window.sidebar.count() - 1
    assert window.pages.currentIndex() == window.pages.count() - 1
    window.close()
    app.processEvents()


def test_support_page_separates_nsa_acknowledgement_from_author_and_donations(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.navigate_to_view("support_author") is True
    page = window.pages.currentWidget()
    text = " ".join(label.text() for label in page.findChildren(QLabel))

    assert "Author / Developer" in text
    assert "Liquidsky Network Security" in text
    assert "MSAA is developed and maintained independently." in text
    assert "Community Acknowledgements" in text
    assert "Thank you to the NSA" in text
    assert "does not imply endorsement, affiliation, certification, or approval" in text
    assert "NSA sponsor" not in text
    assert "NSA author" not in text

    acknowledgement = page.findChild(QLabel, "supportCommunityAcknowledgementsBody")
    assert acknowledgement is not None
    assert "Patreon" not in acknowledgement.text()
    assert "Buy Me a Coffee" not in acknowledgement.text()
    window.close()
    app.processEvents()


def test_support_links_are_canonical_production_values() -> None:
    assert SUPPORT_LINKS == {
        "developer": "Liquidsky Network Security",
        "github": "https://github.com/fuzzlove",
        "website": "https://liquidskysecurity.com",
        "patreon": "https://patreon.com/fuzzlove",
        "buy_me_a_coffee": "https://buymeacoffee.com/fuzzlove",
    }


def test_donation_qr_asset_and_metadata_are_production_values() -> None:
    qr_path = get_donation_qr_path()
    metadata_path = get_donation_qr_metadata_path()
    assert qr_path.exists()
    assert qr_path.stat().st_size > 1000
    assert metadata_path.exists()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["target_url"] == SUPPORT_LINKS["patreon"]
    assert metadata["developer"] == "Liquidsky Network Security"
    assert metadata["verified"] is True
    assert "qrcode" in metadata.get("generator", "")
    combined = qr_path.name + metadata_path.read_text(encoding="utf-8")
    assert "example.com" not in combined
    assert "localhost" not in combined
    assert "placeholder" not in combined.lower()


def test_usage_readme_path_uses_pyinstaller_bundle(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    bundled_readme = tmp_path / "README.md"
    bundled_readme.write_text("# Bundled README", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window._usage_readme_path() == bundled_readme
    window.close()
    app.processEvents()
