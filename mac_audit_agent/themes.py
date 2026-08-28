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
    is_light: bool = False
    description: str = "General-purpose appearance."

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
            "is_light": self.is_light,
            "description": self.description,
        }


THEMES: dict[str, Theme] = {
    "System": Theme(
        "System", "#111827", "#F0F6FC", "rgba(24, 31, 46, 220)", "#58A6FF",
        "#B42318", "#E5A23A", "#6EA6E8", "#8B949E", "#1F6FEB", "#30363D",
        description="Follow the current macOS light or dark appearance while preserving MSAA severity semantics.",
    ),
    "Light": Theme(
        "Light", "#F6F8FB", "#1F2937", "rgba(255, 255, 255, 236)", "#2563EB",
        "#B42318", "#D97706", "#2563EB", "#6B7280", "#1F6FEB", "#E5E7EB",
        is_light=True, description="Bright neutral surfaces with restrained color and crisp dark text.",
    ),
    "Dark": Theme(
        "Dark", "#111827", "#F0F6FC", "rgba(24, 31, 46, 220)", "#58A6FF",
        "#B42318", "#E5A23A", "#6EA6E8", "#8B949E", "#1F6FEB", "#30363D",
        description="Low-glare dark surfaces with clear text and restrained semantic color.",
    ),
    "Default Dark": Theme(
        "Default Dark",
        background="#111827",
        foreground="#F0F6FC",
        card_background="rgba(24, 31, 46, 220)",
        accent="#58A6FF",
        critical="#B42318",
        high="#E5A23A",
        medium="#6EA6E8",
        low="#8B949E",
        button_primary="#1F6FEB",
        button_secondary="#30363D",
        font_family=None,
        transparency_level=0.85,
    ),
    "Forensic Blue": Theme("Forensic Blue", "#0E1524", "#EEF4FF", "rgba(18, 28, 48, 230)", "#7BB6FF", "#B42318", "#D29922", "#6EA6E8", "#8692A6", "#2156C3", "#2D3644", None, 0.88),
    "Red Team Amber": Theme("Red Team Amber", "#18110D", "#FFF6EB", "rgba(38, 27, 18, 232)", "#F4B860", "#B9382E", "#D97706", "#C4A86A", "#9A8A75", "#8A4F0A", "#403223", None, 0.88),
    "Matrix Green": Theme("Matrix Green", "#09130C", "#E7F9EB", "rgba(12, 26, 16, 230)", "#62D18B", "#B42318", "#B7791F", "#7ACB9A", "#6C7F6D", "#116530", "#214132", None, 0.88),
    "Minimal Light": Theme("Minimal Light", "#F6F8FB", "#1F2937", "rgba(255, 255, 255, 236)", "#2563EB", "#B42318", "#D97706", "#2563EB", "#6B7280", "#1F6FEB", "#E5E7EB", None, 0.78, True, "Bright neutral surfaces with restrained color and crisp dark text."),
    "High Contrast": Theme("High Contrast", "#000000", "#FFFFFF", "rgba(18, 18, 18, 255)", "#00E5FF", "#D90429", "#FF9F1A", "#56B4FF", "#C9D1D9", "#005FCC", "#202020", None, 0.98),
    "Retro Terminal": Theme("Retro Terminal", "#041005", "#B7F7C5", "rgba(8, 20, 10, 240)", "#6AF08E", "#B42318", "#B98A16", "#7CE0A4", "#7E9A84", "#175C2D", "#13271A", None, 0.9),
    "Warm Paper": Theme(
        "Warm Paper", "#F3EBDD", "#29241D", "rgba(255, 250, 240, 248)", "#175E75",
        "#A61B1B", "#A34A00", "#175E75", "#5B615E", "#175E75", "#DDD0BA",
        None, 0.97, True, "Low-glare warm surfaces for long reading sessions and reduced blue-light preference.",
    ),
    "Soft Slate": Theme(
        "Soft Slate", "#202832", "#E6EDF3", "rgba(45, 56, 69, 245)", "#8FC7E8",
        "#B9382E", "#C58A24", "#8FC7E8", "#AAB7C4", "#356A86", "#3B4856",
        None, 0.94, False, "Reduced-glare charcoal with gentler contrast for light-sensitive users.",
    ),
    "Color-Vision Safe": Theme(
        "Color-Vision Safe", "#101820", "#F4F7FA", "rgba(28, 40, 51, 250)", "#56B4E9",
        "#D55E00", "#E69F00", "#56B4E9", "#B8C2CC", "#0072B2", "#34495A",
        None, 0.97, False, "Blue, orange, and neutral cues chosen to remain distinct across common color-vision differences.",
    ),
    "Cream & Ink": Theme(
        "Cream & Ink", "#FFFDF7", "#17202A", "rgba(255, 255, 255, 252)", "#244A73",
        "#9F1D35", "#8A4B08", "#244A73", "#59636E", "#244A73", "#E8E2D6",
        None, 0.99, True, "Clean off-white reading surface with strong ink-like text and subdued borders.",
    ),
}

DEFAULT_THEME_NAME = "Default Dark"


def _hex_rgb(value: str) -> tuple[int, int, int]:
    text = str(value).strip().lstrip("#")
    if len(text) != 6:
        raise ValueError(f"Expected #RRGGBB color, got {value!r}")
    return int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)


def contrast_ratio(foreground: str, background: str) -> float:
    """Return the WCAG relative-luminance contrast ratio for solid colors."""
    def luminance(color: str) -> float:
        channels = []
        for value in _hex_rgb(color):
            normalized = value / 255.0
            channels.append(normalized / 12.92 if normalized <= 0.04045 else ((normalized + 0.055) / 1.055) ** 2.4)
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def readable_text_color(background: str) -> str:
    """Choose the higher-contrast neutral text color for a solid surface."""
    candidates = ("#FFFFFF", "#000000")
    return max(candidates, key=lambda candidate: contrast_ratio(candidate, background))


def blend_colors(base: str, overlay: str, overlay_weight: float) -> str:
    """Blend two solid colors so interaction states stay in-theme."""
    weight = max(0.0, min(1.0, float(overlay_weight)))
    base_rgb, overlay_rgb = _hex_rgb(base), _hex_rgb(overlay)
    values = [round(left * (1.0 - weight) + right * weight) for left, right in zip(base_rgb, overlay_rgb)]
    return "#" + "".join(f"{value:02X}" for value in values)


def theme_names() -> list[str]:
    return list(THEMES.keys())


def theme_for_name(name: str | None) -> Theme:
    return THEMES.get(str(name or "").strip(), THEMES[DEFAULT_THEME_NAME])


def theme_stylesheet(theme: Theme, *, accessibility_override: bool = False) -> str:
    card_bg = theme.card_background
    if accessibility_override:
        card_bg = "rgba(255, 255, 255, 255)" if theme.is_light else "rgba(18, 18, 18, 255)"
    font = f"font-family: '{theme.font_family}';" if theme.font_family else ""
    input_bg = blend_colors(theme.background, "#FFFFFF" if theme.is_light else "#000000", 0.72 if theme.is_light else 0.22)
    border = blend_colors(theme.background, theme.accent, 0.38 if accessibility_override else 0.26)
    scrollbar_bg = blend_colors(theme.background, "#FFFFFF" if theme.is_light else "#000000", 0.18)
    scrollbar_handle = theme.accent
    hover_bg = blend_colors(theme.background, theme.accent, 0.24 if theme.is_light else 0.30)
    hover_fg = theme.foreground
    disabled_fg = blend_colors(theme.background, theme.foreground, 0.48)
    disabled_bg = blend_colors(theme.background, theme.foreground, 0.12)
    muted_fg = blend_colors(theme.background, theme.foreground, 0.72)
    subtle_fg = blend_colors(theme.background, theme.foreground, 0.60)
    navigation_bg = blend_colors(theme.background, theme.accent, 0.08)
    card_border = blend_colors(theme.background, theme.accent, 0.22)
    selection_fg = readable_text_color(theme.button_primary)
    accent_fg = readable_text_color(theme.accent)
    warning_fg = readable_text_color(theme.high)
    urgent_fg = readable_text_color(theme.critical)
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
            border: 1px solid {card_border};
            border-radius: 12px;
        }}
        QFrame[metricCard="true"] {{
            background: {card_bg};
            border: 1px solid {card_border};
            border-radius: 10px;
        }}
        QFrame[interactiveCard="true"] {{
            background: {card_bg};
            border: 1px solid {card_border};
            border-radius: 12px;
        }}
        QFrame[interactiveCard="true"]:hover,
        QFrame[interactiveCard="true"]:focus {{
            background: {hover_bg};
            border: 2px solid {theme.accent};
        }}
        QLabel[textRole="operationalState"] {{
            color: {theme.foreground};
            font-size: 18px;
            font-weight: 800;
        }}
        QLabel[textRole="cardAction"] {{
            color: {theme.accent};
            font-size: 12px;
            font-weight: 700;
        }}
        QLabel[textRole="muted"] {{
            color: {muted_fg};
        }}
        QLabel[textRole="metric"] {{
            color: {theme.foreground};
            font-size: 25px;
            font-weight: 750;
        }}
        QLabel[textRole="cardTitle"] {{
            color: {theme.foreground};
            font-size: 16px;
            font-weight: 750;
        }}
        QLabel[textRole="sectionTitle"] {{
            color: {theme.foreground};
            font-size: 14px;
            font-weight: 700;
        }}
        QLabel#pageHeaderTitleLabel {{
            color: {theme.foreground};
        }}
        QLabel#pageHeaderSubtitleLabel,
        QLabel#sectionHeaderDescriptionLabel {{
            color: {muted_fg};
        }}
        QWidget#leftNavigation {{
            background: {navigation_bg};
            border: 1px solid {card_border};
            border-radius: 12px;
        }}
        QFrame#productBrand {{
            background: transparent;
            border: none;
            border-bottom: 1px solid {card_border};
        }}
        QLabel#productBrandTitle {{
            color: {theme.foreground};
            font-size: 18px;
            font-weight: 800;
        }}
        QLabel#productBrandSubtitle {{
            color: {muted_fg};
            font-size: 11px;
        }}
        QLineEdit#navigationFilter {{
            min-height: 32px;
            padding: 2px 9px;
            border-radius: 8px;
        }}
        QLabel#navigationNoResults {{
            color: {muted_fg};
            padding: 8px;
        }}
        QListWidget#mainNavigation {{
            background: transparent;
            border: none;
            outline: none;
        }}
        QListWidget#mainNavigation::item {{
            border: 1px solid transparent;
            border-radius: 7px;
            padding: 4px 9px;
        }}
        QListWidget#mainNavigation::item:hover {{
            background: {hover_bg};
            color: {hover_fg};
        }}
        QListWidget#mainNavigation::item:selected {{
            background: {theme.button_primary};
            color: {selection_fg};
            border: 1px solid {theme.accent};
        }}
        QListWidget#mainNavigation QScrollBar:vertical {{
            width: 10px;
            margin: 2px 0;
        }}
        QFrame#dashboardHero {{
            border-color: {theme.accent};
        }}
        QLabel#dashboardPrivacyCallout {{
            background: {card_bg};
            border-left: 3px solid {theme.accent};
            border-radius: 6px;
            padding: 10px 12px;
        }}
        QTableWidget, QListWidget, QTextEdit, QTextBrowser, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
            background: {input_bg};
            color: {theme.foreground};
            border: 1px solid {border};
            border-radius: 8px;
        }}
        QLineEdit:focus, QTextEdit:focus, QTextBrowser:focus, QPlainTextEdit:focus, QComboBox:focus, QTableWidget:focus, QListWidget:focus {{
            border: 2px solid {theme.accent};
        }}
        QTableWidget::item, QListWidget::item {{
            padding: 5px 7px;
        }}
        QTableWidget::item:selected, QListWidget::item:selected, QComboBox QAbstractItemView::item:selected {{
            background: {theme.button_primary};
            color: {selection_fg};
        }}
        QLineEdit, QTextEdit, QTextBrowser, QPlainTextEdit {{
            selection-background-color: {theme.accent};
            selection-color: {accent_fg};
        }}
        QAbstractScrollArea {{
            border: 1px solid rgba(148, 163, 184, 150);
        }}
        QScrollBar:vertical {{
            background: {scrollbar_bg};
            width: 18px;
            margin: 2px;
            border: 1px solid {border};
            border-radius: 7px;
        }}
        QScrollBar:horizontal {{
            background: {scrollbar_bg};
            height: 18px;
            margin: 2px;
            border: 1px solid {border};
            border-radius: 7px;
        }}
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background: {scrollbar_handle};
            border: 2px solid {theme.background};
            border-radius: 6px;
            min-height: 36px;
            min-width: 36px;
        }}
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background: {theme.foreground};
            border: 2px solid {theme.accent};
        }}
        QScrollBar::add-line, QScrollBar::sub-line {{
            width: 0px;
            height: 0px;
            border: none;
            background: transparent;
        }}
        QScrollBar::add-page, QScrollBar::sub-page {{
            background: {card_border};
            border-radius: 6px;
        }}
        QPushButton {{
            background: {theme.button_secondary};
            color: {theme.foreground};
            border: 1px solid {border};
            border-radius: 6px;
            /* Qt adds vertical padding and borders to min-height. Keep the
               resulting 32px control compatible with button-factory caps. */
            min-height: 20px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background: {hover_bg};
            color: {hover_fg};
        }}
        QPushButton:disabled {{
            color: {disabled_fg};
            background: {disabled_bg};
        }}
        QPushButton[role="primary"] {{
            background: {theme.button_primary};
            color: {selection_fg};
            border: 1px solid {theme.accent};
        }}
        QPushButton[role="warning"] {{
            background: {theme.high};
            color: {warning_fg};
            border: 1px solid {warning_fg};
        }}
        QPushButton[role="urgent"] {{
            background: {theme.critical};
            color: {urgent_fg};
            border: 1px solid {urgent_fg};
        }}
        QPushButton[buttonVariant="export"], QPushButton[buttonVariant="success"] {{
            background: {theme.button_primary};
            color: {selection_fg};
            border: 1px solid {theme.accent};
        }}
        QPushButton[buttonVariant="link"] {{
            background: transparent;
            color: {theme.accent};
            border: 1px solid transparent;
        }}
        QTabWidget::pane {{
            border: 1px solid {card_border};
            border-radius: 8px;
        }}
        QTabBar::tab {{
            background: {navigation_bg};
            color: {muted_fg};
            border: 1px solid {card_border};
            padding: 7px 11px;
            min-height: 24px;
        }}
        QTabBar::tab:selected {{
            background: {theme.button_primary};
            color: {selection_fg};
            border-color: {theme.accent};
        }}
        QTabBar::tab:hover:!selected {{
            color: {theme.foreground};
            border-color: {theme.accent};
        }}
        QMenuBar {{
            background: {navigation_bg};
            color: {theme.foreground};
            border-bottom: 1px solid {card_border};
            padding: 2px 4px;
        }}
        QMenuBar::item {{
            border-radius: 5px;
            padding: 5px 8px;
        }}
        QMenuBar::item:selected, QMenu::item:selected {{
            background: {theme.button_primary};
            color: {selection_fg};
        }}
        QMenu {{
            background: {card_bg};
            color: {theme.foreground};
            border: 1px solid {card_border};
            padding: 5px;
        }}
        QStatusBar {{
            background: {navigation_bg};
            color: {subtle_fg};
            border-top: 1px solid {card_border};
        }}
        QHeaderView::section {{
            background: {navigation_bg};
            color: {theme.foreground};
            border: none;
            border-bottom: 1px solid {card_border};
            padding: 7px;
            font-weight: 700;
        }}
        QTableCornerButton::section {{
            background: {navigation_bg};
            border: 1px solid {card_border};
        }}
        QToolTip {{
            background: {card_bg};
            color: {theme.foreground};
            border: 1px solid {theme.accent};
            padding: 5px;
        }}
        QLabel[severity="critical"], QLabel[severity="high"] {{
            font-weight: 700;
        }}
    """
