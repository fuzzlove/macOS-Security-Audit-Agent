from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from mac_audit_agent.help.contextual_help import make_help_button


class PageHeader(QWidget):
    """Single primary header for a major MSAA view."""

    def __init__(
        self,
        title: str,
        subtitle: str = "",
        *,
        parent: QWidget | None = None,
        help_topic_id: str | None = None,
        status_badge: QWidget | None = None,
        actions: list[QWidget] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("primaryPageHeader")
        self.setProperty("pageHeaderTitle", title)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(4)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("pageHeaderTitleLabel")
        self.title_label.setStyleSheet("font-size: 20px; font-weight: 800;")
        self.title_label.setWordWrap(True)
        text_layout.addWidget(self.title_label)
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("pageHeaderSubtitleLabel")
        self.subtitle_label.setProperty("textRole", "muted")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        text_layout.addWidget(self.subtitle_label)
        layout.addLayout(text_layout, 1)

        if status_badge is not None:
            layout.addWidget(status_badge, alignment=Qt.AlignTop)
        if actions:
            for action in actions:
                layout.addWidget(action, alignment=Qt.AlignTop)
        if help_topic_id:
            layout.addWidget(make_help_button(parent, help_topic_id), alignment=Qt.AlignTop)


class SectionHeader(QWidget):
    """Specific secondary header used below a PageHeader."""

    def __init__(self, title: str, description: str = "", *, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sectionHeader")
        self.setProperty("sectionHeaderTitle", title)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("sectionHeaderTitleLabel")
        self.title_label.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.title_label.setWordWrap(True)
        layout.addWidget(self.title_label)
        self.description_label = QLabel(description)
        self.description_label.setObjectName("sectionHeaderDescriptionLabel")
        self.description_label.setProperty("textRole", "muted")
        self.description_label.setWordWrap(True)
        self.description_label.setVisible(bool(description))
        layout.addWidget(self.description_label)
