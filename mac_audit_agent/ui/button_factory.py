from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QPushButton, QSizePolicy

from mac_audit_agent.ui.button_styles import BUTTON_SIZES, ButtonSize, ButtonVariant
from mac_audit_agent.ui.button_text import normalize_button_text


def create_button(
    text: str,
    *,
    variant: str = ButtonVariant.SECONDARY.value,
    size: str = ButtonSize.NORMAL.value,
    tooltip: str | None = None,
    accessible_name: str | None = None,
    icon: QIcon | None = None,
    min_width: int | None = None,
    max_width: int | None = None,
    on_click: Callable[[], None] | None = None,
    allow_wrap: bool = False,
) -> QPushButton:
    label, fallback_tooltip = normalize_button_text(text)
    button = QPushButton(label)
    if icon is not None:
        button.setIcon(icon)
    spec = BUTTON_SIZES.get(size, BUTTON_SIZES[ButtonSize.NORMAL.value])
    button.setMinimumHeight(spec.min_height)
    button.setMaximumHeight(spec.max_height)
    if min_width is not None or spec.min_width:
        button.setMinimumWidth(min_width if min_width is not None else spec.min_width)
    button.setMaximumWidth(max_width if max_width is not None else spec.max_width)
    button.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
    button.setProperty("buttonVariant", variant)
    role = {
        ButtonVariant.PRIMARY.value: "primary",
        ButtonVariant.WARNING.value: "warning",
        ButtonVariant.REPAIR.value: "urgent",
        ButtonVariant.DANGER.value: "urgent",
        ButtonVariant.DESTRUCTIVE_CONFIRM.value: "urgent",
    }.get(variant)
    if role:
        button.setProperty("role", role)
    final_tooltip = tooltip or fallback_tooltip
    if final_tooltip:
        button.setToolTip(final_tooltip)
    elif len(str(text or "")) > 20:
        button.setToolTip(str(text))
    button.setAccessibleName(accessible_name or label)
    if button.toolTip():
        button.setAccessibleDescription(button.toolTip())
    if allow_wrap:
        button.setProperty("allowWrap", True)
    if on_click is not None:
        button.clicked.connect(on_click)
    return button


def create_primary_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.PRIMARY.value, **kwargs)


def create_secondary_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.SECONDARY.value, **kwargs)


def create_compact_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.COMPACT.value, size=ButtonSize.COMPACT.value, **kwargs)


def create_sidebar_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.SIDEBAR.value, size=ButtonSize.COMPACT.value, max_width=150, **kwargs)


def create_toolbar_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.TOOLBAR.value, size=ButtonSize.COMPACT.value, **kwargs)


def create_repair_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.REPAIR.value, **kwargs)


def create_export_button(text: str, **kwargs) -> QPushButton:
    return create_button(text, variant=ButtonVariant.EXPORT.value, **kwargs)


def create_icon_button(text: str = "", **kwargs) -> QPushButton:
    tooltip = kwargs.get("tooltip")
    accessible_name = kwargs.get("accessible_name")
    if not tooltip or not accessible_name:
        raise ValueError("Icon buttons require tooltip and accessible_name.")
    return create_button(text, variant=ButtonVariant.ICON.value, size=ButtonSize.ICON_ONLY.value, **kwargs)


__all__ = [
    "create_button",
    "create_primary_button",
    "create_secondary_button",
    "create_compact_button",
    "create_sidebar_button",
    "create_toolbar_button",
    "create_repair_button",
    "create_export_button",
    "create_icon_button",
]
