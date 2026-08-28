from __future__ import annotations

from datetime import datetime, timezone

from mac_audit_agent.health.evaluator import SensorHealthEvaluator
from mac_audit_agent.health.models import (
    CoverageLevel,
    PermissionState,
    SensorHealthSnapshot,
    SensorState,
)
from mac_audit_agent.health.providers import RansomwareMonitorProvider
from mac_audit_agent.health.policies import SensorHealthPolicy


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


class EndpointFixture:
    def __init__(self, *, initialized: bool = True) -> None:
        self.snapshot = SensorHealthSnapshot(
            sensor_id="endpoint_security",
            process_alive=initialized,
            initialized=initialized,
            events_received_total=1_600_000,
            events_processed_total=1_600_000,
            events_delivered_total=1_600_000,
            last_process_heartbeat=NOW,
            last_collection_activity=NOW,
            last_processing_activity=NOW,
            last_delivery_activity=NOW,
            permission_state=PermissionState.GRANTED,
        )

    def health_snapshot(self) -> SensorHealthSnapshot:
        return self.snapshot

    def perform_self_test(self):  # pragma: no cover - provider protocol only
        raise AssertionError("not used")

    def recover(self, _reason):  # pragma: no cover - provider protocol only
        raise AssertionError("not used")


def test_raw_endpoint_transport_counts_are_not_ransomware_analysis_counts() -> None:
    provider = RansomwareMonitorProvider(
        EndpointFixture(),
        telemetry_reader=lambda _path: {
            "database_available": True,
            "observer_running": False,
            "findings_total": 0,
        },
    )

    snapshot = provider.health_snapshot()

    assert snapshot.events_received_total == 0
    assert snapshot.events_processed_total == 0
    assert snapshot.events_persisted_total == 0
    assert snapshot.metadata["upstream_endpoint_events_received_total"] == 1_600_000
    assert snapshot.metadata["telemetry_source"] == "none"
    assert snapshot.capabilities[0].coverage is CoverageLevel.NONE


def test_development_observer_reports_limited_pipeline_without_false_stall() -> None:
    provider = RansomwareMonitorProvider(
        EndpointFixture(initialized=False),
        telemetry_reader=lambda _path: {
            "database_available": True,
            "observer_running": True,
            "last_heartbeat": NOW.isoformat(),
            "last_observation": NOW.isoformat(),
            "observations_total": 73,
            "observations_dropped_total": 0,
            "recent_window_count": 12,
            "findings_total": 2,
            "pending_findings": 1,
            "last_finding": NOW.isoformat(),
            "yara_active": False,
            "yara_rule_count": 0,
        },
    )

    snapshot = provider.health_snapshot()
    evaluated = SensorHealthEvaluator().evaluate(snapshot, SensorHealthPolicy(), now=NOW)

    assert snapshot.events_received_total == 2
    assert snapshot.events_processed_total == 2
    assert snapshot.events_persisted_total == 2
    assert snapshot.events_delivered_total == 2
    assert snapshot.metadata["findings_pending_notification"] == 1
    assert snapshot.metadata["observations_total"] == 73
    assert snapshot.capabilities[0].coverage is CoverageLevel.LIMITED
    assert snapshot.dependencies[0].required is False
    assert evaluated.state is SensorState.DEGRADED
    assert evaluated.reason_code.value == "FALLBACK_MODE_ACTIVE"
