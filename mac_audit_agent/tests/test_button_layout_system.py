from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget, QVBoxLayout

from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.ui.button_factory import create_button, create_compact_button, create_icon_button
from mac_audit_agent.ui.button_layout_auditor import audit_buttons, static_button_source_audit
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_button_factory_applies_compact_size_and_tooltip() -> None:
    _app()
    button = create_compact_button("Refresh Network Intelligence")
    assert button.minimumHeight() >= 26
    assert button.maximumHeight() <= 32
    assert button.text() == "Refresh"
    assert "Network Intelligence" in button.toolTip()
    assert button.accessibleName() == "Refresh"


def test_normal_button_height_within_limit() -> None:
    _app()
    button = create_button("Apply Settings")
    assert button.minimumHeight() >= 32
    assert button.maximumHeight() <= 38


def test_icon_button_requires_tooltip_and_accessible_name() -> None:
    _app()
    with pytest.raises(ValueError):
        create_icon_button("?")
    button = create_icon_button("?", tooltip="Open help.", accessible_name="Help")
    assert button.toolTip() == "Open help."
    assert button.accessibleName() == "Help"
    assert button.maximumWidth() <= 34


def test_runtime_button_auditor_detects_visible_button_records() -> None:
    _app()
    root = QWidget()
    layout = QVBoxLayout(root)
    button = QPushButton("Short")
    button.setToolTip("Short action.")
    layout.addWidget(button)
    root.show()
    records = audit_buttons(root)
    assert any(record["text"] == "Short" for record in records)
    root.close()


def test_responsive_action_row_reserves_height_for_wrapped_buttons() -> None:
    app = _app()
    root = QWidget()
    layout = QVBoxLayout(root)
    actions = ResponsiveActionRow()
    buttons = [QPushButton(f"Action {index} with detail") for index in range(4)]
    actions.add_buttons(buttons)
    following = QLabel("Content after actions")
    layout.addWidget(actions)
    layout.addWidget(following)
    layout.addStretch(1)

    root.resize(300, 300)
    root.show()
    app.processEvents()

    assert actions.height() >= actions.heightForWidth(actions.width())
    assert all(actions.rect().contains(button.geometry()) for button in buttons)
    assert following.geometry().top() > actions.geometry().bottom()
    root.close()


def test_static_button_source_audit_discovers_buttons() -> None:
    records = static_button_source_audit()
    assert records
    assert any(record["text"] == "Help Menu ?" for record in records)


def test_pre_uat_registry_includes_button_layout_checks() -> None:
    ids = {check.check_id for check in build_registry()}
    for check_id in {
        "ui.buttons.inventory",
        "ui.buttons.no_overlap",
        "ui.buttons.no_cropping",
        "ui.buttons.size_policy",
        "ui.buttons.tooltip_accessibility",
        "ui.buttons.navigation_proportional",
        "ui.buttons.action_rows_responsive",
        "ui.buttons.visible_connected",
    }:
        assert check_id in ids
