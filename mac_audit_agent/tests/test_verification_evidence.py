from __future__ import annotations

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.quality.verification_evidence import evidence_is_fresh, latest_evidence, record_verification_evidence


def test_records_and_loads_fresh_interactive_alert_evidence(tmp_path) -> None:
    path = tmp_path / "verification_evidence.json"
    record = record_verification_evidence(
        check_id="alert.bottom_right_rendering.interactive",
        command="python3 -m mac_audit_agent.quality.pre_uat_audit --alerts --interactive",
        started_at=utc_now_iso(),
        completed_at=utc_now_iso(),
        status="pass",
        exit_code=0,
        evidence_summary="Interactive alert verified.",
        ttl_hours=24,
        details={"trace_id": "trace-1", "visible_alert_id": "alert-1"},
        path=path,
    )

    loaded = latest_evidence("alert.bottom_right_rendering.interactive", path)

    assert loaded is not None
    assert loaded["evidence_id"] == record.evidence_id
    assert evidence_is_fresh(loaded, max_age_hours=24)
    assert loaded["details"]["trace_id"] == "trace-1"


def test_failed_or_missing_evidence_is_not_fresh(tmp_path) -> None:
    path = tmp_path / "verification_evidence.json"
    record_verification_evidence(
        check_id="alert.bottom_right_rendering.interactive",
        command="cmd",
        started_at=utc_now_iso(),
        completed_at=utc_now_iso(),
        status="fail",
        exit_code=1,
        evidence_summary="failed",
        path=path,
    )

    assert not evidence_is_fresh(latest_evidence("alert.bottom_right_rendering.interactive", path), max_age_hours=24)
    assert latest_evidence("missing", path) is None
