from __future__ import annotations


HELP_MENU_BUTTON_MIN_HEIGHT = 28
HELP_MENU_BUTTON_MAX_HEIGHT = 34
HELP_MENU_BUTTON_MAX_WIDTH = 122
HELP_MENU_BUTTON_STYLE = """
QPushButton#globalHelpMenuButton {
    font-size: 12px;
    font-weight: 500;
    padding: 4px 8px;
    text-align: left;
    border-radius: 6px;
}
QPushButton#globalHelpMenuButton:hover {
    border: 1px solid #58A6FF;
}
QPushButton#globalHelpMenuButton:focus {
    border: 2px solid #58A6FF;
}
"""


__all__ = ["HELP_MENU_BUTTON_MIN_HEIGHT", "HELP_MENU_BUTTON_MAX_HEIGHT", "HELP_MENU_BUTTON_MAX_WIDTH", "HELP_MENU_BUTTON_STYLE"]
