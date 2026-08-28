from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mac_audit_agent.security_operations import SecurityOperationsOverviewBuilder


NOW = datetime(2026, 8, 25, 18, 0, tzinfo=timezone.utc)


def test_overview_prioritizes_findings_and_sensor_coverage_without_raw_event_noise():
    overview = SecurityOperationsOverviewBuilder().build(
        findings=[
            {"id": "f-1", "title": "Unsigned persistent helper", "severity": "critical", "confidence": "high", "category": "Persistence", "why_this_matters": "Privileged persistence and unsigned code are correlated."},
            {"id": "f-2", "title": "Expected admin", "severity": "informational", "confidence": "medium", "category": "Identity"},
        ],
        events=[
            {"event_id": "e-1", "timestamp": NOW.isoformat(), "event_type": "network_anomaly", "severity": "high", "confidence": "high", "rule_id": "net-1", "process_name": "helper"},
            {"event_id": "old", "timestamp": (NOW - timedelta(days=2)).isoformat(), "event_type": "persistence_change", "severity": "high", "confidence": "high"},
        ],
        sensor_report={"required_sensors_total": 3, "required_sensors_healthy": 2, "sensors": [{"sensor_id": "endpoint_security", "state": "FAILED", "reason": "permission denied", "metadata": {"criticality": "CRITICAL"}}]},
        protection_status={"status": "partially_installed"},
        scan_available=True,
        now=NOW,
    )
    assert overview.posture == "CRITICAL"
    assert overview.last_24_hours["network_anomalies"] == 1
    assert overview.last_24_hours["persistence_changes"] == 0
    assert overview.needs_attention[0].severity == "critical"
    assert any(item.title.startswith("Sensor degraded") for item in overview.needs_attention)
    cards = {item.card_id: item for item in overview.cards}
    assert cards["sensor_coverage"].summary == "2/3 critical sensors operational"
    assert cards["active_threats"].evidence_count == 1


def test_overview_preserves_unknown_when_no_evidence_exists():
    overview = SecurityOperationsOverviewBuilder().build(now=NOW)
    assert overview.posture == "UNKNOWN"
    assert overview.posture_summary == "Run an assessment to establish current posture"
    assert {item.route for item in overview.cards}
    assert all(item.route for item in overview.cards)
    assert overview.needs_attention[0].title == "Assessment required"


def test_high_severity_low_confidence_event_is_not_presented_as_confirmed_threat():
    overview = SecurityOperationsOverviewBuilder().build(
        events=[{"event_id": "e-1", "timestamp": NOW.isoformat(), "event_type": "suspicious_process", "severity": "critical", "confidence": "low"}],
        now=NOW,
    )
    card = next(item for item in overview.cards if item.card_id == "active_threats")
    assert card.evidence_count == 0
    assert "No high-confidence" in card.summary


def test_degraded_protection_is_counted_and_dns_concern_is_not_healthy():
    overview = SecurityOperationsOverviewBuilder().build(
        protection_status={"status": "partially_installed"},
        dns_status={"status": "concern", "explanation": "Resolver has not been client validated."},
        scan_available=True,
        now=NOW,
    )

    assert overview.posture == "DEGRADED"
    assert overview.posture_summary == "1 high-priority condition requires review"
    dns = next(item for item in overview.cards if item.card_id == "dns")
    assert dns.state == "REVIEW"
    assert dns.severity == "high"
