from __future__ import annotations

from typing import ClassVar

from PySide6.QtWidgets import QWidget

from mac_audit_agent.help.help_viewer import HelpViewer


class HelpController:
    _instance: ClassVar["HelpController | None"] = None

    def __init__(self) -> None:
        self.viewer: HelpViewer | None = None

    @classmethod
    def instance(cls) -> "HelpController":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def open_help_center(self, parent: QWidget | None = None) -> HelpViewer:
        return self.navigate_to_topic("help_center", parent=parent)

    def open_help_topic(self, topic_id: str, parent: QWidget | None = None) -> HelpViewer:
        return self.navigate_to_topic(topic_id, parent=parent)

    def navigate_to_topic(self, topic_id: str, parent: QWidget | None = None) -> HelpViewer:
        if self.viewer is None:
            self.viewer = HelpViewer(topic_id, None)
        else:
            self.viewer.open_topic(topic_id)
        self.viewer.show()
        self.viewer.raise_()
        self.viewer.activateWindow()
        return self.viewer


DEFAULT_HELP_CONTROLLER = HelpController.instance()
