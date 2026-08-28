from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ButtonVariant(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    DANGER = "danger"
    WARNING = "warning"
    SUCCESS = "success"
    NEUTRAL = "neutral"
    LINK = "link"
    COMPACT = "compact"
    ICON = "icon"
    TOOLBAR = "toolbar"
    SIDEBAR = "sidebar"
    CARD_ACTION = "card_action"
    DESTRUCTIVE_CONFIRM = "destructive_confirm"
    REPAIR = "repair"
    EXPORT = "export"


class ButtonSize(str, Enum):
    COMPACT = "compact"
    NORMAL = "normal"
    LARGE = "large"
    ICON_ONLY = "icon_only"


@dataclass(frozen=True)
class ButtonSizeSpec:
    min_height: int
    max_height: int
    padding_x: int
    padding_y: int
    min_width: int = 0
    max_width: int = 16777215


BUTTON_SIZES: dict[str, ButtonSizeSpec] = {
    ButtonSize.COMPACT.value: ButtonSizeSpec(26, 32, 8, 4, 0, 180),
    ButtonSize.NORMAL.value: ButtonSizeSpec(32, 38, 12, 5, 0, 260),
    ButtonSize.LARGE.value: ButtonSizeSpec(40, 48, 16, 7, 0, 320),
    ButtonSize.ICON_ONLY.value: ButtonSizeSpec(28, 34, 0, 0, 28, 34),
}

VARIANT_COLORS: dict[str, tuple[str, str, str]] = {
    ButtonVariant.PRIMARY.value: ("#175CD3", "#FFFFFF", "#B2DDFF"),
    ButtonVariant.SECONDARY.value: ("#1F2937", "#F9FAFB", "#475467"),
    ButtonVariant.NEUTRAL.value: ("#344054", "#FFFFFF", "#667085"),
    ButtonVariant.COMPACT.value: ("#1F2937", "#F9FAFB", "#475467"),
    ButtonVariant.TOOLBAR.value: ("#1F2937", "#F9FAFB", "#475467"),
    ButtonVariant.SIDEBAR.value: ("#111827", "#F9FAFB", "#374151"),
    ButtonVariant.CARD_ACTION.value: ("#1F2937", "#F9FAFB", "#475467"),
    ButtonVariant.EXPORT.value: ("#064E3B", "#FFFFFF", "#6EE7B7"),
    ButtonVariant.SUCCESS.value: ("#067647", "#FFFFFF", "#ABEFC6"),
    ButtonVariant.WARNING.value: ("#B54708", "#FFFFFF", "#FEDF89"),
    ButtonVariant.REPAIR.value: ("#B42318", "#FFFFFF", "#FFCDCA"),
    ButtonVariant.DANGER.value: ("#912018", "#FFFFFF", "#FDA29B"),
    ButtonVariant.DESTRUCTIVE_CONFIRM.value: ("#7A0000", "#FFFFFF", "#FFB4A8"),
    ButtonVariant.LINK.value: ("transparent", "#58A6FF", "transparent"),
    ButtonVariant.ICON.value: ("#1F2937", "#F9FAFB", "#475467"),
}


def button_stylesheet(variant: str = "secondary", size: str = "normal") -> str:
    spec = BUTTON_SIZES.get(size, BUTTON_SIZES[ButtonSize.NORMAL.value])
    background, foreground, border = VARIANT_COLORS.get(variant, VARIANT_COLORS[ButtonVariant.SECONDARY.value])
    border_rule = "border: none;" if border == "transparent" else f"border: 1px solid {border};"
    return f"""
QPushButton {{
    background: {background};
    color: {foreground};
    {border_rule}
    border-radius: 6px;
    padding: {spec.padding_y}px {spec.padding_x}px;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton:hover {{
    border: 1px solid #58A6FF;
}}
QPushButton:pressed {{
    background: #111827;
}}
QPushButton:disabled {{
    background: #344054;
    color: #98A2B3;
    border: 1px solid #475467;
}}
"""


__all__ = ["ButtonVariant", "ButtonSize", "BUTTON_SIZES", "button_stylesheet"]
