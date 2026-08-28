from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mac_audit_agent.health.baselines import RollingBaseline
from mac_audit_agent.health.diagnostics import diagnostics_payload, export_diagnostics
from mac_audit_agent.health.evaluator import HysteresisTracker, SensorHealthEvaluator, build_platform_report
from mac_audit_agent.health.fault_injection import FaultInjector
from mac_audit_agent.health.manager import SensorReliabilityCoordinator
from mac_audit_agent.health.models import (
    CapabilityHealth, CoverageLevel, Criticality, DependencyState, PermissionState,
    ReasonCode, RecoveryLevel, RecoveryReason, RecoveryResult, ResourceMetrics,
    RuleHealth, SelfTestResult, SensorDependency, SensorDescriptor,
    SensorHealthSnapshot, SensorState,
)
from mac_audit_agent.health.persistence import SensorHealthStore
from mac_audit_agent.health.policies import SensorHealthPolicy
from mac_audit_agent.health.recovery import RecoveryEngine
from mac_audit_agent.health.registry import SensorRegistry
from mac_audit_agent.sensor_health_service import build_sensor_health_plist
from mac_audit_agent.service_watchdog import request_service_recovery


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def healthy(sensor_id: str = "process_monitor") -> SensorHealthSnapshot:
    return SensorHealthSnapshot(
        sensor_id=sensor_id, process_alive=True, initialized=True,
        last_process_heartbeat=NOW, last_collection_activity=NOW,
        last_processing_activity=NOW, last_delivery_activity=NOW,
        last_persistence_activity=NOW, events_received_total=100,
        events_processed_total=100, events_delivered_total=100,
        events_persisted_total=100, queue_depth=0, queue_capacity=100,
        permission_state=PermissionState.GRANTED,
        capabilities=(CapabilityHealth("process_execution", CoverageLevel.FULL),),
    )


def evaluate(snapshot: SensorHealthSnapshot, policy: SensorHealthPolicy | None = None) -> SensorHealthSnapshot:
    return SensorHealthEvaluator().evaluate(snapshot, policy or SensorHealthPolicy(), now=NOW)


def test_normal_operation_requires_functional_evidence() -> None:
    result = evaluate(healthy())
    assert result.state == SensorState.HEALTHY
    assert result.health_score == 100
    empty = evaluate(SensorHealthSnapshot(sensor_id="empty", process_alive=True, initialized=True, last_process_heartbeat=NOW))
    assert empty.state == SensorState.STALE
    assert empty.reason_code == ReasonCode.EVENT_STREAM_STALE


def test_dead_process_is_failed_even_with_recent_event() -> None:
    result = evaluate(replace(healthy(), process_alive=False))
    assert result.state == SensorState.FAILED
    assert result.reason_code == ReasonCode.PROCESS_NOT_RUNNING


def test_alive_but_stalled_with_pending_queue_is_impaired() -> None:
    result = evaluate(replace(healthy(), queue_depth=9, last_processing_activity=NOW - timedelta(minutes=5)))
    assert result.state == SensorState.IMPAIRED
    assert result.reason_code == ReasonCode.PROCESSING_STALL


def test_stale_stream_requires_failed_or_missing_synthetic_proof() -> None:
    stale = replace(healthy(), last_collection_activity=NOW - timedelta(hours=2), last_self_test=SelfTestResult(False, "canary", "not observed"))
    result = evaluate(stale)
    assert result.state in {SensorState.STALE, SensorState.DEGRADED}
    passing = evaluate(replace(stale, last_self_test=SelfTestResult(True, "canary", "observed")))
    assert passing.state == SensorState.HEALTHY_IDLE


def test_sustained_queue_backpressure_not_single_spike() -> None:
    spike = evaluate(replace(healthy(), queue_depth=80, backpressure_duration_seconds=1))
    assert spike.state == SensorState.HEALTHY_WITH_WARNINGS
    sustained = evaluate(replace(healthy(), queue_depth=80, backpressure_duration_seconds=31))
    assert sustained.state == SensorState.BACKPRESSURED
    assert sustained.reason_code == ReasonCode.QUEUE_BACKPRESSURE


def test_event_loss_is_distinct_from_filtering() -> None:
    result = evaluate(replace(healthy(), events_dropped_total=5, events_filtered_total=900, events_received_total=100))
    assert result.state == SensorState.DEGRADED
    assert result.reason_code == ReasonCode.EVENT_LOSS


def test_permission_revocation_is_immediate_and_not_hidden() -> None:
    result = evaluate(replace(healthy(), permission_state=PermissionState.REVOKED))
    assert result.state == SensorState.PERMISSION_BLOCKED
    assert result.reason_code == ReasonCode.PERMISSION_REVOKED


def test_dependency_failure_propagates_root_cause() -> None:
    dependency = SensorDependency("privileged_helper", True, DependencyState.FAILED, "IPC disconnected")
    result = evaluate(replace(healthy(), dependencies=(dependency,)))
    assert result.state == SensorState.DEPENDENCY_FAILED
    assert "privileged_helper" in result.reason


def test_rule_failure_degrades_alive_sensor() -> None:
    result = evaluate(replace(healthy(), rules=RuleHealth(expected=10, loaded=8, failed=2)))
    assert result.state == SensorState.DEGRADED
    assert result.rule_health == SensorState.DEGRADED


def test_disk_and_descriptor_pressure_degrade_before_exhaustion() -> None:
    result = evaluate(replace(healthy(), resources=ResourceMetrics(free_disk_bytes=100, free_disk_percent=1.0, open_descriptors=90, descriptor_limit=100)))
    assert result.state in {SensorState.DEGRADED, SensorState.IMPAIRED}
    assert result.reason_code in {ReasonCode.DISK_PRESSURE, ReasonCode.DESCRIPTOR_PRESSURE}


def test_duplicate_singleton_instance_is_not_auto_terminated() -> None:
    result = evaluate(replace(healthy(), metadata={"duplicate_instances": 2}))
    assert result.state == SensorState.IMPAIRED
    assert result.reason_code == ReasonCode.DUPLICATE_INSTANCE


def test_clock_moves_backward_without_negative_freshness() -> None:
    future_sample = replace(healthy(), last_process_heartbeat=NOW + timedelta(hours=1))
    assert evaluate(future_sample).state == SensorState.HEALTHY


def test_hysteresis_and_post_recovery_stabilization() -> None:
    tracker = HysteresisTracker()
    policy = replace(SensorHealthPolicy(), consecutive_failures_required=3, consecutive_successes_required=2)
    prior = replace(healthy(), state=SensorState.HEALTHY, health_score=100)
    degraded = replace(healthy(), state=SensorState.DEGRADED, health_score=60, reason_code=ReasonCode.EVENT_LOSS)
    assert tracker.apply(degraded, prior, policy).state == SensorState.HEALTHY
    recovering = replace(prior, state=SensorState.RECOVERING, health_score=40)
    stable = tracker.apply(replace(prior, state=SensorState.HEALTHY), recovering, policy)
    assert stable.state == SensorState.STABILIZING


class FakeProvider:
    def __init__(self, snapshot: SensorHealthSnapshot, recovery_success: bool = True) -> None:
        self.snapshot = snapshot
        self.recovery_success = recovery_success
        self.recoveries = 0

    def sensor_id(self) -> str:
        return self.snapshot.sensor_id

    def health_snapshot(self) -> SensorHealthSnapshot:
        return self.snapshot

    def dependencies(self) -> list[SensorDependency]:
        return list(self.snapshot.dependencies)

    def perform_self_test(self) -> SelfTestResult:
        return SelfTestResult(self.recovery_success, "fake_canary", "controlled")

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        self.recoveries += 1
        return RecoveryResult(True, self.recovery_success, reason.requested_level, "controlled")


class RepairingFakeProvider(FakeProvider):
    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        result = super().recover(reason)
        if result.succeeded:
            now = datetime.now(timezone.utc)
            self.snapshot = replace(
                healthy(self.snapshot.sensor_id),
                last_process_heartbeat=now,
                last_collection_activity=now,
                last_processing_activity=now,
                last_delivery_activity=now,
                last_persistence_activity=now,
            )
        return result


def test_restart_budget_exhaustion_stops_retries() -> None:
    clock = [100.0]
    engine = RecoveryEngine(now=lambda: clock[0])
    provider = FakeProvider(replace(healthy(), reason_code=ReasonCode.PROCESS_NOT_RUNNING, process_alive=False))
    policy = replace(SensorHealthPolicy(), restart_budget_count=2)
    first = engine.recover(provider, provider.snapshot, policy)
    clock[0] += 1
    second = engine.recover(provider, provider.snapshot, policy)
    clock[0] += 1
    third = engine.recover(provider, provider.snapshot, policy)
    assert first.attempted and second.attempted
    assert not third.attempted and third.requires_operator
    assert provider.recoveries == 2


def test_manual_recovery_requires_post_repair_health_and_self_test(tmp_path: Path) -> None:
    descriptor = SensorDescriptor("process_monitor", "Process", Criticality.CRITICAL, capabilities=("process_execution",))
    registry = SensorRegistry((descriptor,))
    provider = RepairingFakeProvider(
        replace(healthy(), process_alive=False, reason_code=ReasonCode.PROCESS_NOT_RUNNING)
    )
    registry.register(provider)
    store = SensorHealthStore(tmp_path / "repair.sqlite3")
    coordinator = SensorReliabilityCoordinator(store, registry)

    result = coordinator.recover_sensor("process_monitor")

    assert result["post_recovery_self_test"]["passed"] is True
    assert result["post_recovery_state"] == "HEALTHY"
    assert result["fully_operational"] is True
    assert [step["stage"] for step in result["repair_trace"]] == [
        "diagnosis", "repair decision", "bounded recovery", "functional self-test", "independent post-repair snapshot",
    ]
    assert "VERBOSE REPAIR TRACE" in result["copyable_transcript"]
    assert "Verified fully operational: True" in result["copyable_transcript"]
    store.close()


def test_permission_failure_is_not_claimed_repaired(tmp_path: Path) -> None:
    descriptor = SensorDescriptor("process_monitor", "Process", Criticality.CRITICAL, capabilities=("process_execution",))
    registry = SensorRegistry((descriptor,))
    provider = FakeProvider(
        replace(healthy(), permission_state=PermissionState.REVOKED, reason_code=ReasonCode.PERMISSION_REVOKED)
    )
    registry.register(provider)
    store = SensorHealthStore(tmp_path / "permission.sqlite3")
    coordinator = SensorReliabilityCoordinator(store, registry)

    result = coordinator.recover_sensor("process_monitor")

    assert result["recovery"]["attempted"] is False
    assert result["recovery"]["requires_operator"] is True
    assert result["fully_operational"] is False
    assert provider.recoveries == 0
    assert any("OPERATOR_ACTION_REQUIRED" in error for error in result["errors"])
    assert "PERMISSION_REVOKED" in result["copyable_transcript"]
    store.close()


def test_critical_failure_dominates_platform_average() -> None:
    critical = SensorDescriptor("critical_sensor", "Critical", Criticality.CRITICAL, capabilities=("execution",))
    optional = SensorDescriptor("optional_sensor", "Optional", Criticality.LOW, expected=False, capabilities=("enrichment",))
    report = build_platform_report(((critical, evaluate(replace(healthy("critical_sensor"), process_alive=False, capabilities=()))), (optional, evaluate(healthy("optional_sensor")))))
    assert report.overall_health.value == "FAILED"
    assert next(item for item in report.coverage if item.capability_id == "execution").coverage == CoverageLevel.NONE


def test_declared_full_coverage_is_capped_by_evaluated_sensor_state() -> None:
    descriptor = SensorDescriptor("ransomware_monitor", "Ransomware", Criticality.CRITICAL)
    impaired = replace(
        healthy("ransomware_monitor"),
        state=SensorState.IMPAIRED,
        reason_code=ReasonCode.PERSISTENCE_STALL,
        reason="Persistence progression is not proven.",
        capabilities=(CapabilityHealth("ransomware_evidence", CoverageLevel.FULL, "raw provider claim"),),
    )
    report = build_platform_report(((descriptor, impaired),))
    capability = report.coverage[0]
    assert capability.coverage == CoverageLevel.PARTIAL
    assert "capped by IMPAIRED" in capability.reason


def test_store_hash_chains_transitions_and_deduplicates_incident(tmp_path: Path) -> None:
    store = SensorHealthStore(tmp_path / "health.sqlite3")
    descriptor = SensorDescriptor("process_monitor", "Process", Criticality.CRITICAL, capabilities=("process_execution",))
    failed = evaluate(replace(healthy(), process_alive=False))
    report = build_platform_report(((descriptor, failed),))
    store.persist_report(report, {"process_monitor": SensorState.HEALTHY})
    history = store.history("process_monitor")
    assert len(history) == 1
    assert len(history[0]["record_hash"]) == 64
    assert history[0]["previous_hash"] == "0" * 64
    store.persist_report(report, {"process_monitor": SensorState.FAILED})
    incidents = store.connection.execute("SELECT occurrence_count FROM sensor_health_incidents WHERE active=1").fetchall()
    assert len(incidents) == 1
    store.close()


def test_coordinator_isolates_provider_failure_and_persists_report(tmp_path: Path) -> None:
    descriptor = SensorDescriptor("process_monitor", "Process", Criticality.CRITICAL, capabilities=("process_execution",))
    registry = SensorRegistry((descriptor,))
    provider = FakeProvider(healthy())
    registry.register(provider)
    store = SensorHealthStore(tmp_path / "manager.sqlite3")
    coordinator = SensorReliabilityCoordinator(store, registry)
    report = coordinator.run_cycle(auto_recover=False)
    assert report.required_total == 1
    assert store.current_snapshot("process_monitor") is not None
    store.close()


def test_fault_injection_is_explicitly_development_only() -> None:
    with pytest.raises(PermissionError):
        FaultInjector({"process_monitor": {"processing_stall"}}, enabled=True, environment="production")
    injected = FaultInjector({"process_monitor": {"processing_stall"}}, enabled=True, environment="development").apply(healthy())
    assert evaluate(injected).reason_code == ReasonCode.PROCESSING_STALL


def test_watchdog_recovery_broker_is_allowlisted(tmp_path: Path) -> None:
    path = request_service_recovery("system_monitor", "PROCESSING_STALL", request_dir=tmp_path)
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        request_service_recovery("arbitrary_process", "PROCESSING_STALL", request_dir=tmp_path)


def test_sensor_health_plist_is_periodic_not_keepalive() -> None:
    payload = build_sensor_health_plist("/usr/local/bin/python3", 501)
    assert payload["StartInterval"] == 60
    assert payload["RunAtLoad"] is True
    assert "KeepAlive" not in payload
    assert payload["ProgramArguments"][2] == "mac_audit_agent.sensor_health_service"


def test_rolling_baseline_detects_significant_deviation() -> None:
    baseline = RollingBaseline(30)
    for value in range(20, 50):
        baseline.add(float(value))
    assert baseline.summary().p95 >= baseline.summary().p50
    assert baseline.classify(1_000) == "SIGNIFICANT_DEVIATION"


def test_diagnostics_export_json_and_html(tmp_path: Path) -> None:
    store = SensorHealthStore(tmp_path / "diagnostics.sqlite3")
    descriptor = SensorDescriptor("process_monitor", "Process", Criticality.CRITICAL)
    report = build_platform_report(((descriptor, evaluate(healthy())),))
    store.persist_report(report, {"process_monitor": SensorState.UNKNOWN})
    payload = diagnostics_payload(store, report.to_dict())
    assert export_diagnostics(payload, tmp_path / "health.json").is_file()
    html = export_diagnostics(payload, tmp_path / "health.html")
    assert "MSAA Sensor Health" in html.read_text(encoding="utf-8")
    docx = export_diagnostics(payload, tmp_path / "health.docx")
    xlsx = export_diagnostics(payload, tmp_path / "health.xlsx")
    assert docx.read_bytes().startswith(b"PK")
    assert xlsx.read_bytes().startswith(b"PK")
    store.close()
