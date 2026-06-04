from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.themes import DEFAULT_THEME_NAME, theme_names


class ThemeSettingsPanel(QFrame):
    theme_changed = Signal(str, bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("themeSettingsPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._build_ui()
        self.set_theme(DEFAULT_THEME_NAME, False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Skins")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        subtitle = QLabel("Choose a local control panel skin. High contrast overrides low-contrast styling.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        grid = QGridLayout()
        self.theme_combo = QComboBox()
        for name in theme_names():
            self.theme_combo.addItem(name)
        self.high_contrast = QCheckBox("Accessibility mode / High contrast")
        self.preview_label = QLabel("Preview")
        self.preview_label.setStyleSheet("font-weight: 700; color: #D6E4FF;")
        self.preview_body = QLabel("High/critical alert colors remain distinct regardless of skin.")
        self.preview_body.setWordWrap(True)
        self.preview_body.setStyleSheet("color: #D6E4FF;")
        self.apply_button = QPushButton("Apply Skin")
        self.apply_button.setMinimumHeight(36)
        self.apply_button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.apply_button.clicked.connect(self._emit_change)
        grid.addWidget(QLabel("Skin"), 0, 0)
        grid.addWidget(self.theme_combo, 0, 1)
        grid.addWidget(self.high_contrast, 1, 0, 1, 2)
        grid.addWidget(self.preview_label, 2, 0, 1, 2)
        grid.addWidget(self.preview_body, 3, 0, 1, 2)
        grid.addWidget(self.apply_button, 4, 0, 1, 2)
        layout.addLayout(grid)

    def set_theme(self, theme_name: str, accessibility: bool) -> None:
        index = self.theme_combo.findText(theme_name)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        self.high_contrast.setChecked(bool(accessibility))

    def current_theme(self) -> tuple[str, bool]:
        return self.theme_combo.currentText(), self.high_contrast.isChecked()

    def _emit_change(self) -> None:
        self.theme_changed.emit(*self.current_theme())

