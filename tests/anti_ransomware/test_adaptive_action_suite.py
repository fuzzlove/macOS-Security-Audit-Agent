from __future__ import annotations

import pytest

from mac_audit_agent.anti_ransomware.adaptive_action_suite import (
    ACTION_CASES,
    run_adaptive_action_suite,
)


def test_all_twenty_adaptive_ransomware_action_tests_pass_safely() -> None:
    report = run_adaptive_action_suite()
    assert len(ACTION_CASES) == 20
    assert report["case_count"] == 20
    assert report["passed_count"] == 20
    assert report["failed_count"] == 0
    assert report["all_passed"] is True
    assert set(report["safety"].values()) == {False}
    assert all(item["automatic_containment_performed"] is False for item in report["results"])


@pytest.mark.parametrize("case_id", [f"AR-ACT-{number:02d}" for number in range(1, 21)])
def test_each_adaptive_action_case_can_run_independently(case_id: str) -> None:
    report = run_adaptive_action_suite({case_id})
    assert report["case_count"] == 1
    assert report["results"][0]["case_id"] == case_id
    assert report["results"][0]["passed"] is True


def test_replay_case_rejects_duplicate_events() -> None:
    result = run_adaptive_action_suite({"AR-ACT-20"})["results"][0]
    assert result["duplicate_events_rejected"] == 10
    assert result["window_evidence"]["event_count"] == 10


def test_unknown_action_case_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown adaptive action"):
        run_adaptive_action_suite({"AR-ACT-99"})
