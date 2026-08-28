from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.themes import DEFAULT_THEME_NAME, theme_for_name, theme_names


class ThemeSettingsPanel(QFrame):
    theme_changed = Signal(str, bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("themeSettingsPanel")
        self.setProperty("themeCard", True)
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._build_ui()
        self.set_theme(DEFAULT_THEME_NAME, False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(16)

        title = QLabel("Appearance")
        title.setProperty("textRole", "cardTitle")
        subtitle = QLabel("Choose an appearance suited to your contrast, glare, and color-vision preferences.")
        subtitle.setWordWrap(True)
        subtitle.setProperty("textRole", "muted")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        skin_label = QLabel("Theme")
        skin_label.setProperty("textRole", "sectionTitle")
        self.theme_combo = QComboBox()
        for name in theme_names():
            self.theme_combo.addItem(name)
        self.theme_combo.setMinimumHeight(36)
        self.theme_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.theme_combo.currentTextChanged.connect(self._update_preview)

        contrast_label = QLabel("Contrast")
        contrast_label.setProperty("textRole", "sectionTitle")
        self.high_contrast = QCheckBox("High contrast")
        self.high_contrast.setMinimumHeight(36)
        self.high_contrast.setToolTip("Increases contrast while preserving severity colors.")
        self.high_contrast.toggled.connect(lambda _checked: self._update_preview())

        self.preview_frame = QFrame()
        self.preview_frame.setObjectName("skinPreviewFrame")
        self.preview_frame.setMinimumHeight(170)
        self.preview_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        preview_layout = QVBoxLayout(self.preview_frame)
        preview_layout.setContentsMargins(14, 14, 14, 14)
        preview_layout.setSpacing(10)
        self.preview_label = QLabel("Preview")
        self.preview_label.setStyleSheet("font-weight: 700;")
        self.preview_body = QLabel("Severity colors stay distinct across themes.")
        self.preview_body.setWordWrap(True)
        self.swatch_row = QHBoxLayout()
        self.swatch_row.setSpacing(8)
        self.swatches: list[QLabel] = []
        for _index in range(4):
            swatch = QLabel()
            swatch.setFixedSize(38, 18)
            self.swatches.append(swatch)
            self.swatch_row.addWidget(swatch)
        self.swatch_row.addStretch(1)
        preview_layout.addWidget(self.preview_label)
        preview_layout.addWidget(self.preview_body)
        preview_layout.addLayout(self.swatch_row)
        preview_layout.addStretch(1)

        self.apply_button = QPushButton("Apply Appearance")
        self.apply_button.setProperty("role", "primary")
        self.apply_button.setMinimumHeight(36)
        self.apply_button.setMinimumWidth(140)
        self.apply_button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.apply_button.clicked.connect(self._emit_change)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(0, 2, 0, 0)
        action_row.addStretch(1)
        action_row.addWidget(self.apply_button)

        grid.addWidget(skin_label, 0, 0)
        grid.addWidget(contrast_label, 0, 1)
        grid.addWidget(self.theme_combo, 1, 0)
        grid.addWidget(self.high_contrast, 1, 1)
        grid.addWidget(self.preview_frame, 2, 0, 1, 2)
        grid.addLayout(action_row, 3, 0, 1, 2)
        layout.addLayout(grid)
        layout.addStretch(1)

    def set_theme(self, theme_name: str, accessibility: bool) -> None:
        index = self.theme_combo.findText(theme_name)
        if index >= 0:
            self.theme_combo.setCurrentIndex(index)
        self.high_contrast.setChecked(bool(accessibility))
        self._update_preview()

    def current_theme(self) -> tuple[str, bool]:
        return self.theme_combo.currentText(), self.high_contrast.isChecked()

    def _emit_change(self) -> None:
        self.theme_changed.emit(*self.current_theme())

    def _update_preview(self) -> None:
        theme = theme_for_name(self.theme_combo.currentText())
        self.preview_body.setText(theme.description + " Severity is also communicated with text labels, not color alone.")
        card_background = theme.card_background
        if self.high_contrast.isChecked():
            card_background = "rgba(255, 255, 255, 255)" if theme.is_light else "rgba(18, 18, 18, 255)"
        self.preview_frame.setStyleSheet(
            f"""
            QFrame#skinPreviewFrame {{
                background: {card_background};
                border: 1px solid {theme.accent};
                border-radius: 8px;
            }}
            QFrame#skinPreviewFrame QLabel {{
                color: {theme.foreground};
            }}
            """
        )
        for swatch, color in zip(self.swatches, [theme.critical, theme.high, theme.medium, theme.low]):
            swatch.setStyleSheet(f"background: {color}; border: 1px solid rgba(255, 255, 255, 110); border-radius: 4px;")
