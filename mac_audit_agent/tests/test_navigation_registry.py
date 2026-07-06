from __future__ import annotations

from mac_audit_agent.ui.navigation_registry import NavigationItem, ordered_navigation_items, validate_navigation_order


def test_support_author_is_pinned_last_even_when_future_tabs_are_inserted() -> None:
    items = [
        NavigationItem("dashboard", "Dashboard", order=10),
        NavigationItem("support_author", "Support the Author", order=9999, pinned_position="last"),
        NavigationItem("future_feature", "Future Feature", order=10000),
    ]
    ordered = ordered_navigation_items(items)
    assert [item.id for item in ordered] == ["dashboard", "future_feature", "support_author"]
    assert validate_navigation_order(items) == []


def test_navigation_validation_fails_when_support_is_missing_or_duplicated() -> None:
    assert validate_navigation_order([NavigationItem("dashboard", "Dashboard", order=10)])
    duplicate = [
        NavigationItem("dashboard", "Dashboard", order=10),
        NavigationItem("support_author", "Support the Author", order=9999, pinned_position="last"),
        NavigationItem("support_author", "Support the Author", order=9998, pinned_position="last"),
    ]
    assert any("Duplicate" in item for item in validate_navigation_order(duplicate))


def test_navigation_validation_fails_when_support_is_not_last() -> None:
    items = [
        NavigationItem("support_author", "Support the Author", order=1),
        NavigationItem("dashboard", "Dashboard", order=10),
    ]
    assert any("final" in item or "before" in item for item in validate_navigation_order(items))
