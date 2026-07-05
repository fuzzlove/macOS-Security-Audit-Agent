from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.help.glossary import GLOSSARY
from mac_audit_agent.help.help_controller import HelpController
from mac_audit_agent.help.help_registry import get_help_topic, get_related_topics, list_help_topics, search_help_topics
from mac_audit_agent.help.help_viewer import MISSING_TOPIC_MESSAGE, HelpViewer
from mac_audit_agent.help.contextual_help import CONTEXT_HELP_TOPICS
from mac_audit_agent.ui.main_window import MainWindow


REQUIRED_TOPICS = {
    "help_center",
    "how_msaa_works",
    "alert_severity",
    "operational_health",
    "integrity_verification",
    "apple_exposure",
    "persistence_intelligence",
    "network_intelligence",
    "live_response",
    "family_safety",
    "reports_exports",
    "troubleshooting",
    "glossary",
    "about_msaa",
}


def test_help_registry_has_required_complete_topics() -> None:
    topics = {topic.topic_id: topic for topic in list_help_topics()}
    assert REQUIRED_TOPICS.issubset(topics)
    for topic in topics.values():
        assert topic.title.strip()
        assert topic.summary.strip()
        assert topic.content.strip()
        assert "What the user should do:" in topic.content
        assert topic.related_topics
        assert "coming soon" not in topic.content.lower()
        assert "placeholder" not in topic.content.lower()


def test_related_topics_and_glossary_terms_resolve() -> None:
    topic_ids = {topic.topic_id for topic in list_help_topics()}
    glossary_ids = {term.lower() for term in GLOSSARY}
    for topic in list_help_topics():
        assert set(topic.related_topics).issubset(topic_ids)
        assert {term.lower() for term in topic.glossary_terms}.issubset(glossary_ids)
        assert get_related_topics(topic.topic_id)


def test_help_search_matches_content_and_empty_query() -> None:
    assert any(topic.topic_id == "network_intelligence" for topic in search_help_topics("gateway"))
    assert any(topic.topic_id == "integrity_verification" for topic in search_help_topics("SHA-256"))
    assert len(search_help_topics("")) == len(list_help_topics())
    assert search_help_topics("definitely-no-such-help-term") == []


def test_help_viewer_opens_topic_missing_topic_and_search() -> None:
    app = QApplication.instance() or QApplication([])
    viewer = HelpViewer("help_center")
    assert viewer.current_topic_id == "help_center"
    viewer.open_topic("missing-topic")
    assert MISSING_TOPIC_MESSAGE in viewer.content_view.toPlainText()
    viewer.search_field.setText("severity")
    assert "Severity" in viewer.title_label.text() or "severity" in viewer.content_view.toPlainText().lower()
    viewer.search_field.setText("no-results-for-this")
    assert "No help results found for: no-results-for-this" in viewer.content_view.toPlainText()
    viewer.close()
    app.processEvents()


def test_contextual_help_mapping_targets_specific_topics() -> None:
    assert CONTEXT_HELP_TOPICS["Dashboard"] == "dashboard"
    assert CONTEXT_HELP_TOPICS["Integrity Verification"] == "integrity_verification"
    assert CONTEXT_HELP_TOPICS["Apple Exposure Assessment"] == "apple_exposure"
    assert CONTEXT_HELP_TOPICS["Persistence Intelligence"] == "persistence_intelligence"
    assert CONTEXT_HELP_TOPICS["Network Intelligence"] == "network_intelligence"
    for topic_id in CONTEXT_HELP_TOPICS.values():
        assert get_help_topic(topic_id) is not None


def test_main_window_has_single_global_help_menu_entry(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    global_help_buttons = [
        button
        for button in window.findChildren(QPushButton)
        if button.text() == "Help Menu ?" or button.objectName() == "globalHelpMenuButton"
    ]
    help_actions = [action for action in window.findChildren(QAction) if action.property("help_topic_id")]
    menu_titles = [action.text().replace("&", "") for action in window.menuBar().actions()]

    assert len(global_help_buttons) == 1
    assert global_help_buttons[0] is window.global_help_button
    assert window.global_help_button.parent() is window.left_nav
    assert window.left_nav.layout().itemAt(0).widget() is window.global_help_button
    assert help_actions == []
    assert "Help" not in menu_titles
    window.close()
    app.processEvents()


def test_help_controller_is_singleton() -> None:
    assert HelpController.instance() is HelpController.instance()


def test_help_controller_reuses_single_help_center_viewer() -> None:
    app = QApplication.instance() or QApplication([])
    controller = HelpController()

    first_viewer = controller.open_help_center()
    second_viewer = controller.open_help_topic("network_intelligence")
    third_viewer = controller.navigate_to_topic("integrity_verification")

    assert first_viewer is second_viewer is third_viewer
    assert third_viewer.objectName() == "helpCenterViewer"
    assert third_viewer.current_topic_id == "integrity_verification"

    third_viewer.close()
    app.processEvents()


def test_global_help_menu_button_is_visible_labeled_accessible_and_left_positioned(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    button = window.global_help_button

    assert button.text() == "Help Menu ?"
    assert button.text() != "?"
    assert "Help Menu" in button.text()
    assert button.toolTip() == (
        "Open the MSAA Help Center for feature explanations, troubleshooting, "
        "glossary definitions, and safe response guidance."
    )
    assert button.accessibleName() == "Help Menu"
    assert button.accessibleDescription() == "Open the MSAA Help Center"
    assert button.minimumHeight() >= 34
    assert button.sizeHint().width() > 80
    assert window.left_nav.layout().itemAt(0).widget() is button

    window.close()
    app.processEvents()


def test_ui_code_uses_help_controller_instead_of_direct_help_viewer_construction() -> None:
    ui_root = Path(__file__).resolve().parents[1] / "ui"
    offenders: list[str] = []

    for source_path in ui_root.rglob("*.py"):
        source = source_path.read_text()
        if "HelpViewer(" in source:
            offenders.append(str(source_path.relative_to(ui_root.parent.parent)))

    assert offenders == []


def test_no_duplicate_visible_global_help_labels_or_help_menu_actions(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    visible_global_help_buttons = [
        button
        for button in window.findChildren(QPushButton)
        if not button.isHidden() and ("Help Menu" in button.text() or button.accessibleName() == "Help Menu")
    ]
    menu_titles = [action.text().replace("&", "") for action in window.menuBar().actions()]
    menu_help_actions = [
        action
        for action in window.menuBar().findChildren(QAction)
        if "Help Menu" in action.text() or action.property("help_topic_id")
    ]

    assert visible_global_help_buttons == [window.global_help_button]
    assert "Help" not in menu_titles
    assert menu_help_actions == []

    window.close()
    app.processEvents()


def test_global_help_menu_button_opens_help_center_and_reuses_viewer(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    window.global_help_button.click()
    first_viewer = window.help_viewer
    assert first_viewer.current_topic_id == "help_center"
    assert first_viewer.content_view.toPlainText().strip()

    window.open_help_topic("alert_severity")
    assert window.help_viewer is first_viewer
    assert window.help_viewer.current_topic_id == "alert_severity"
    window.global_help_button.click()
    assert window.help_viewer is first_viewer
    assert window.help_viewer.current_topic_id == "help_center"
    window.open_help_topic("network_intelligence")
    assert window.help_viewer is first_viewer
    assert window.help_viewer.current_topic_id == "network_intelligence"

    window.help_viewer.close()
    window.close()
    app.processEvents()


def test_f1_shortcut_action_opens_help_center(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    assert window.help_shortcut_action.shortcut().toString()
    assert window.help_shortcut_action.text() == "Open Help Center"
    window.help_shortcut_action.trigger()
    assert window.help_viewer.current_topic_id == "help_center"

    window.help_viewer.close()
    window.close()
    app.processEvents()


def test_contextual_help_buttons_remain_icon_sized_and_specific(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    contextual_buttons = [
        button
        for button in window.findChildren(QPushButton)
        if button.objectName().startswith("helpButton_")
    ]

    assert contextual_buttons
    assert all(button.text() == "?" for button in contextual_buttons)
    assert all(button.objectName() != "globalHelpMenuButton" for button in contextual_buttons)
    integrity_button = next(button for button in contextual_buttons if button.objectName() == "helpButton_integrity_verification")
    integrity_button.click()
    first_viewer = window.help_viewer
    assert first_viewer.current_topic_id == "integrity_verification"
    integrity_button.click()
    assert window.help_viewer is first_viewer
    assert window.help_viewer.content_view.toPlainText().strip()

    window.help_viewer.close()
    window.close()
    app.processEvents()


def test_contextual_help_buttons_route_to_same_help_center_instance(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    contextual_buttons = [
        button
        for button in window.findChildren(QPushButton)
        if button.objectName().startswith("helpButton_")
    ]

    assert contextual_buttons
    for button in contextual_buttons:
        topic_id = button.objectName().removeprefix("helpButton_")
        assert get_help_topic(topic_id) is not None
        button.click()
        assert window.help_viewer.current_topic_id == topic_id
        assert window.help_viewer.objectName() == "helpCenterViewer"
        assert window.help_controller.viewer is window.help_viewer

    help_viewers = [
        viewer
        for viewer in QApplication.topLevelWidgets()
        if isinstance(viewer, HelpViewer) and viewer.objectName() == "helpCenterViewer" and viewer.isVisible()
    ]
    assert len(help_viewers) == 1

    window.help_viewer.close()
    window.close()
    app.processEvents()


def test_dashboard_integrity_help_button_is_in_card_title_row(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    button = window.dashboard_integrity_help_button
    card_layout = window.dashboard_integrity_frame.layout()
    title_row_item = card_layout.itemAt(0)
    title_row = title_row_item.layout()

    assert button.objectName() == "helpButton_integrity_verification"
    assert button.text() == "?"
    assert title_row is not None
    assert title_row.itemAt(1).widget() is button
    assert card_layout.itemAt(1).widget() is window.dashboard_integrity_status_label

    window.close()
    app.processEvents()


def test_help_resource_path_fallback_supports_pyinstaller_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert get_help_topic("help_center") is not None
    assert get_help_topic("missing") is None
