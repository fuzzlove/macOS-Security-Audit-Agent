from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtWidgets import QWidget


@dataclass(frozen=True)
class NavigationItem:
    id: str
    title: str
    widget_factory: Callable[[], QWidget] | None = None
    order: int = 0
    pinned_position: str | None = None


def ordered_navigation_items(items: list[NavigationItem]) -> list[NavigationItem]:
    normal = [item for item in items if item.pinned_position != "last"]
    last = [item for item in items if item.pinned_position == "last"]
    return [*sorted(normal, key=lambda item: (item.order, item.title)), *sorted(last, key=lambda item: (item.order, item.title))]


def validate_navigation_order(items: list[NavigationItem]) -> list[str]:
    errors: list[str] = []
    support_items = [item for item in items if item.id == "support_author" or item.title == "Support the Author"]
    if not support_items:
        errors.append("Support the Author navigation item is missing.")
    if len(support_items) > 1:
        errors.append("Duplicate Support the Author navigation items found.")
    ordered = ordered_navigation_items(items)
    if support_items and ordered[-1].id != "support_author":
        errors.append("Support the Author must be the final navigation item.")
    for index, item in enumerate(ordered[:-1]):
        if item.pinned_position == "last":
            errors.append(f"Navigation item {item.id} is pinned last but is not final.")
        if item.id == "support_author":
            errors.append("Support the Author must not appear before other navigation items.")
    return errors


__all__ = ["NavigationItem", "ordered_navigation_items", "validate_navigation_order"]
