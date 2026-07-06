from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QScrollArea, QVBoxLayout, QWidget

from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.ui_text_audit import audit_visible_duplicate_headers


def _page_for(window: MainWindow, name: str) -> QWidget:
    for index in range(window.sidebar.count()):
        if window.sidebar.item(index).text() == name:
            page = window.pages.widget(index)
            if isinstance(page, QScrollArea):
                widget = page.widget()
                assert widget is not None
                return widget
            return page
    raise AssertionError(f"Missing sidebar page: {name}")


def _page_headers(page: QWidget) -> list[QWidget]:
    return [widget for widget in page.findChildren(QWidget) if widget.objectName() == "primaryPageHeader"]


def test_major_views_have_one_primary_page_header(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    expected_titles = {
        "Dashboard": "Dashboard",
        "Apple Exposure Assessment": "Apple Exposure Assessment",
        "Family & Safety": "Family & Safety Center",
        "Persistence Intelligence": "Persistence Intelligence",
        "Network Intelligence": "Network Intelligence",
        "Settings": "Settings",
        "Pre-UAT Audit": "Pre-UAT Audit",
    }
    for sidebar_name, title in expected_titles.items():
        headers = _page_headers(_page_for(window, sidebar_name))
        assert len(headers) == 1, sidebar_name
        assert headers[0].property("pageHeaderTitle") == title

    window.close()
    app.processEvents()


def test_wrapped_panels_do_not_repeat_page_titles(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    checks = {
        "Apple Exposure Assessment": "Apple Exposure Assessment",
        "Family & Safety": "Family & Safety Center",
        "Persistence Intelligence": "Persistence Intelligence",
        "Network Intelligence": "Network Intelligence",
    }
    for sidebar_name, title in checks.items():
        page = _page_for(window, sidebar_name)
        matching_labels = [
            label
            for label in page.findChildren(QLabel)
            if label.text().strip() == title and label.objectName() != "pageHeaderTitleLabel"
        ]
        assert matching_labels == [], sidebar_name

    window.close()
    app.processEvents()


def test_settings_page_has_single_primary_title(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    settings_page = _page_for(window, "Settings")

    headers = _page_headers(settings_page)
    assert len(headers) == 1
    assert headers[0].property("pageHeaderTitle") == "Settings"
    assert "Operational Health" not in [header.property("pageHeaderTitle") for header in headers]
    assert "Monitor Settings" not in [header.property("pageHeaderTitle") for header in headers]

    window.close()
    app.processEvents()


def test_duplicate_header_helper_flags_adjacent_duplicate_labels() -> None:
    app = QApplication.instance() or QApplication([])
    root = QWidget()
    layout = QVBoxLayout(root)
    layout.addWidget(QLabel("Operational Health"))
    layout.addWidget(QLabel("Operational Health"))

    findings = audit_visible_duplicate_headers(root)

    assert findings
    assert findings[0].text == "Operational Health"
    root.close()
    app.processEvents()
