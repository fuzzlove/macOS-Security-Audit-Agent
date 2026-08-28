from __future__ import annotations

from mac_audit_agent.assessment import build_security_assessment
from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.storage import AuditDatabase


def test_assessment_profile_and_depth_use_existing_builder() -> None:
    assessment = build_security_assessment(
        None,
        None,
        [],
        assessment_profile="Apple Security Assessment",
        assessment_depth="Deep",
    )

    assert assessment.assessment_profile == "Apple Security Assessment"
    assert assessment.assessment_depth == "Deep"
    assert assessment.assessment_status == "unavailable"


def test_recent_assessments_preserve_order_for_drift(tmp_path) -> None:
    database = AuditDatabase(tmp_path / "audit.sqlite")
    first = build_security_assessment(None, None, [], assessment_id="first")
    first.created_at = "2026-08-25T10:00:00+00:00"
    second = build_security_assessment(None, None, [], assessment_id="second")
    second.created_at = "2026-08-25T11:00:00+00:00"
    database.record_security_assessment(first)
    database.record_security_assessment(second)

    recent = database.recent_security_assessments(limit=2)

    assert [item["assessment_id"] for item in recent] == ["second", "first"]


def test_profile_scope_and_depth_change_included_runtime_evidence() -> None:
    network_event = BackgroundMonitorEvent(
        event_id="network-1",
        timestamp="2026-08-25T12:00:00+00:00",
        event_type="network_anomaly",
        severity="info",
        source="network_monitor",
        evidence="Unexpected outbound connection requires review.",
    )

    quick = build_security_assessment(None, None, [network_event], assessment_profile="Network Assessment", assessment_depth="Quick")
    deep = build_security_assessment(None, None, [network_event], assessment_profile="Network Assessment", assessment_depth="Deep")
    developer = build_security_assessment(None, None, [network_event], assessment_profile="Developer Security Assessment", assessment_depth="Deep")

    assert quick.info_findings == []
    assert [item["event_type"] for item in deep.info_findings] == ["network_anomaly"]
    assert developer.info_findings == []
    assert "do not constitute certification" in deep.diagnostics["qualification"]
