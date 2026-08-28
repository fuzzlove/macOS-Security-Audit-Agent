from __future__ import annotations

from dataclasses import dataclass

import launcher

from mac_audit_agent.release_features import filter_pre_uat_navigation, pre_uat_requested


@dataclass(frozen=True)
class Item:
    id: str


def test_pre_uat_requires_exact_explicit_flag() -> None:
    assert pre_uat_requested(["--pre-uat"])
    assert not pre_uat_requested([])
    assert not pre_uat_requested(["--developer-mode"])
    assert not pre_uat_requested(["--pre-uat=true"])


def test_release_navigation_removes_pre_uat_only() -> None:
    items = [Item("dashboard"), Item("pre_uat_audit"), Item("support_author")]
    assert [item.id for item in filter_pre_uat_navigation(items, enabled=False)] == ["dashboard", "support_author"]
    assert [item.id for item in filter_pre_uat_navigation(items, enabled=True)] == ["dashboard", "pre_uat_audit", "support_author"]


def test_stage_zero_launcher_accepts_pre_uat_flag() -> None:
    assert launcher._parser().parse_args(["--pre-uat"]).pre_uat is True
