from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Theme:
    name: str
    background: str
    foreground: str
    card_background: str
    accent: str
    critical: str
    high: str
    medium: str
    low: str
    button_primary: str
    button_secondary: str
    font_family: str | None = None
    transparency_level: float = 0.85

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "background": self.background,
            "foreground": self.foreground,
            "card_background": self.card_background,
            "accent": self.accent,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "button_primary": self.button_primary,
            "button_secondary": self.button_secondary,
            "font_family": self.font_family,
            "transparency_level": self.transparency_level,
        }


THEMES: dict[str, Theme] = {
    "Default Dark": Theme(
        "Default Dark",
        background="#111827",
        foreground="#F0F6FC",
        card_background="rgba(24, 31, 46, 220)",
        accent="#58A6FF",
        critical="#D64545",
        high="#E5A23A",
        medium="#6EA6E8",
        low="#8B949E",
        button_primary="#1F6FEB",
        button_secondary="#30363D",
        font_family="Segoe UI",
        transparency_level=0.85,
    ),
    "Forensic Blue": Theme("Forensic Blue", "#0E1524", "#EEF4FF", "rgba(18, 28, 48, 230)", "#7BB6FF", "#D64545", "#D29922", "#6EA6E8", "#8692A6", "#2156C3", "#2D3644", "Segoe UI", 0.88),
    "Red Team Amber": Theme("Red Team Amber", "#18110D", "#FFF6EB", "rgba(38, 27, 18, 232)", "#F4B860", "#E06363", "#F39C12", "#C4A86A", "#9A8A75", "#8A4F0A", "#403223", "Segoe UI", 0.88),
    "Matrix Green": Theme("Matrix Green", "#09130C", "#E7F9EB", "rgba(12, 26, 16, 230)", "#62D18B", "#DB5A5A", "#D8A132", "#7ACB9A", "#6C7F6D", "#116530", "#214132", "Consolas", 0.88),
    "Minimal Light": Theme("Minimal Light", "#F6F8FB", "#1F2937", "rgba(255, 255, 255, 236)", "#2563EB", "#B42318", "#D97706", "#2563EB", "#6B7280", "#1F6FEB", "#E5E7EB", "Segoe UI", 0.78),
    "High Contrast": Theme("High Contrast", "#000000", "#FFFFFF", "rgba(18, 18, 18, 255)", "#00E5FF", "#FF4D5A", "#FF9F1A", "#56B4FF", "#C9D1D9", "#005FCC", "#202020", "Arial", 0.98),
    "Retro Terminal": Theme("Retro Terminal", "#041005", "#B7F7C5", "rgba(8, 20, 10, 240)", "#6AF08E", "#FF5A5A", "#E2B93B", "#7CE0A4", "#7E9A84", "#175C2D", "#13271A", "Monaco", 0.9),
}

DEFAULT_THEME_NAME = "Default Dark"


def theme_names() -> list[str]:
    return list(THEMES.keys())


def theme_for_name(name: str | None) -> Theme:
    return THEMES.get(str(name or "").strip(), THEMES[DEFAULT_THEME_NAME])


def theme_stylesheet(theme: Theme, *, accessibility_override: bool = False) -> str:
    card_bg = theme.card_background
    if accessibility_override:
        card_bg = "rgba(18, 18, 18, 255)" if theme.name != "Minimal Light" else "rgba(255, 255, 255, 255)"
    font = f"font-family: '{theme.font_family}';" if theme.font_family else ""
    return f"""
        QWidget {{
            background: {theme.background};
            color: {theme.foreground};
            {font}
        }}
        QFrame {{
            background-color: transparent;
        }}
        QFrame[themeCard="true"] {{
            background: {card_bg};
            border: 1px solid rgba(148, 163, 184, 100);
            border-radius: 12px;
        }}
        QTableWidget, QListWidget, QTextEdit, QLineEdit, QComboBox {{
            background: rgba(10, 14, 24, 120);
            color: {theme.foreground};
            border: 1px solid rgba(148, 163, 184, 100);
            border-radius: 8px;
        }}
        QAbstractScrollArea {{
            border: 1px solid rgba(148, 163, 184, 150);
        }}
        QScrollBar:vertical {{
            background: rgba(5, 8, 13, 230);
            width: 18px;
            margin: 2px;
            border: 1px solid rgba(255, 255, 255, 180);
            border-radius: 7px;
        }}
        QScrollBar:horizontal {{
            background: rgba(5, 8, 13, 230);
            height: 18px;
            margin: 2px;
            border: 1px solid rgba(255, 255, 255, 180);
            border-radius: 7px;
        }}
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background: #FFD166;
            border: 2px solid #111827;
            border-radius: 6px;
            min-height: 36px;
            min-width: 36px;
        }}
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background: #FFFFFF;
            border: 2px solid #FFD166;
        }}
        QScrollBar::add-line, QScrollBar::sub-line {{
            width: 0px;
            height: 0px;
            border: none;
            background: transparent;
        }}
        QScrollBar::add-page, QScrollBar::sub-page {{
            background: rgba(255, 255, 255, 45);
            border-radius: 6px;
        }}
        QPushButton {{
            background: {theme.button_secondary};
            color: {theme.foreground};
            border: 1px solid rgba(148, 163, 184, 140);
            border-radius: 6px;
            min-height: 34px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background: rgba(76, 89, 113, 220);
        }}
        QPushButton:disabled {{
            color: rgba(240, 246, 252, 100);
            background: rgba(72, 79, 88, 160);
        }}
        QPushButton[role="primary"] {{
            background: {theme.button_primary};
            border: 1px solid {theme.accent};
        }}
        QPushButton[role="warning"] {{
            background: {theme.high};
            border: 1px solid rgba(255, 255, 255, 120);
        }}
        QPushButton[role="urgent"] {{
            background: {theme.critical};
            border: 1px solid rgba(255, 255, 255, 120);
        }}
        QLabel[severity="critical"], QLabel[severity="high"] {{
            font-weight: 700;
        }}
    """
