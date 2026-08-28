from __future__ import annotations

from mac_audit_agent.quality.functional_registry import build_registry


def test_pre_uat_registry_includes_help_menu_layout_checks() -> None:
    ids = {check.check_id for check in build_registry()}
    assert "ui.help_menu_button_proportional" in ids
    assert "ui.help_menu_bottom_left" in ids
