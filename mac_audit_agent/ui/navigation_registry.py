from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtWidgets import QWidget


NAVIGATION_SECTIONS: tuple[str, ...] = (
    "Overview",
    "Protection",
    "Posture & Inventory",
    "Network",
    "Investigation",
    "Workspace",
    "About",
)

_SECTION_BY_ID = {
    "dashboard": "Overview",
    "apple_exposure": "Posture & Inventory",
    "family_safety": "Posture & Inventory",
    "intrusion_detection": "Protection",
    "behavioral_telemetry": "Protection",
    "anti_ransomware": "Protection",
    "sensor_health": "Protection",
    "anti_typosquatting": "Posture & Inventory",
    "clickfix_guard": "Protection",
    "clickfix_awareness": "Workspace",
    "keylogger_detection": "Protection",
    "not_signed": "Posture & Inventory",
    "firewall": "Protection",
    "emergency_protection": "Protection",
    "zero_trust_posture": "Posture & Inventory",
    "add_remove_programs": "Posture & Inventory",
    "persistence_intelligence": "Posture & Inventory",
    "security_research_device": "Posture & Inventory",
    "dns_assurance": "Network",
    "consultant_timesheet": "Workspace",
    "network_monitor": "Network",
    "default_credential_scanner": "Network",
    "code_review": "Posture & Inventory",
    "network_intelligence": "Network",
    "network_segmentation": "Network",
    "investigation_priorities": "Investigation",
    "flight_recorder": "Investigation",
    "alert_center": "Investigation",
    "logs": "Investigation",
    "reliability": "Investigation",
    "system_recovery": "Investigation",
    "apple_diagnostics": "Investigation",
    "visibility_integrity": "Investigation",
    "framework_coverage": "Posture & Inventory",
    "settings": "Workspace",
    "skins": "Workspace",
    "profile": "Workspace",
    "scan_categories": "Posture & Inventory",
    "results": "Posture & Inventory",
    "assessment": "Posture & Inventory",
    "investigation_notes": "Workspace",
    "command_preview": "Workspace",
    "support_author": "About",
}


@dataclass(frozen=True)
class NavigationItem:
    id: str
    title: str
    widget_factory: Callable[[], QWidget] | None = None
    order: int = 0
    pinned_position: str | None = None


def navigation_section(item: NavigationItem | str) -> str:
    """Return the stable product-navigation section for an item."""

    item_id = item.id if isinstance(item, NavigationItem) else str(item)
    return _SECTION_BY_ID.get(item_id, "Workspace")


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


def validate_navigation_and_utility_layout(items: list[NavigationItem], *, utility_control_ids: list[str] | None = None) -> list[str]:
    errors = validate_navigation_order(items)
    help_nav_items = [
        item
        for item in items
        if item.id in {"help", "help_menu", "global_help", "global_help_menu"} or item.title.strip().lower().startswith("help menu")
    ]
    if help_nav_items:
        errors.append("Help Menu must be a sidebar utility action, not a primary navigation item.")
    if utility_control_ids is not None and "globalHelpMenuButton" not in set(utility_control_ids):
        errors.append("Global Help Menu utility button is missing from the sidebar utility footer.")
    return errors


__all__ = [
    "NAVIGATION_SECTIONS",
    "NavigationItem",
    "navigation_section",
    "ordered_navigation_items",
    "validate_navigation_and_utility_layout",
    "validate_navigation_order",
]
