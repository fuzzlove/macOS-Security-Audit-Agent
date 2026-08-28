"""Functional-health evaluation, scoring, hysteresis, and platform coverage."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Iterable

from .models import (
    CapabilityHealth,
    CoverageLevel,
    Criticality,
    DependencyState,
    PermissionState,
    PlatformHealthReport,
    PlatformState,
    ReasonCode,
    SensorDescriptor,
    SensorHealthSnapshot,
    SensorState,
    utc_now,
)
from .policies import SensorHealthPolicy


FAILURE_STATES = {
    SensorState.FAILED, SensorState.UNAVAILABLE, SensorState.PERMISSION_BLOCKED,
    SensorState.CONFIGURATION_ERROR, SensorState.DEPENDENCY_FAILED,
}
DEGRADED_STATES = {
    SensorState.DEGRADED, SensorState.IMPAIRED, SensorState.STALE,
    SensorState.BACKPRESSURED, SensorState.RATE_LIMITED,
}
IMMEDIATE_REASON_CODES = {
    ReasonCode.PROCESS_NOT_RUNNING, ReasonCode.PERMISSION_REVOKED,
    ReasonCode.ENTITLEMENT_MISSING, ReasonCode.SIGNATURE_INVALID,
    ReasonCode.QUEUE_OVERFLOW, ReasonCode.DATABASE_UNAVAILABLE,
    ReasonCode.RESTART_LOOP, ReasonCode.DUPLICATE_INSTANCE,
}


def _age(value: datetime | None, now: datetime) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0.0, (now - value.astimezone(timezone.utc)).total_seconds())


def _state_rank(state: SensorState) -> int:
    return {
        SensorState.UNKNOWN: 20, SensorState.INITIALIZING: 25,
        SensorState.HEALTHY: 100, SensorState.HEALTHY_IDLE: 98,
        SensorState.HEALTHY_WITH_WARNINGS: 85, SensorState.HIGH_LOAD: 82,
        SensorState.DEGRADED: 65, SensorState.BACKPRESSURED: 55,
        SensorState.STALE: 50, SensorState.IMPAIRED: 40,
        SensorState.RECOVERING: 45, SensorState.STABILIZING: 75,
        SensorState.PERMISSION_BLOCKED: 20, SensorState.CONFIGURATION_ERROR: 20,
        SensorState.DEPENDENCY_FAILED: 20, SensorState.RATE_LIMITED: 35,
        SensorState.FAILED: 0, SensorState.UNAVAILABLE: 0,
        SensorState.DISABLED: 0, SensorState.UNSUPPORTED: 0,
        SensorState.MAINTENANCE: 70,
    }.get(state, 0)


class HysteresisTracker:
    """Require sustained evidence while allowing severe failures immediately."""

    def __init__(self) -> None:
        self._candidate: dict[str, SensorState] = {}
        self._count: dict[str, int] = {}

    def apply(self, snapshot: SensorHealthSnapshot, previous: SensorHealthSnapshot | None, policy: SensorHealthPolicy) -> SensorHealthSnapshot:
        desired = snapshot.state
        if previous is None or snapshot.reason_code in IMMEDIATE_REASON_CODES:
            self._candidate[snapshot.sensor_id] = desired
            self._count[snapshot.sensor_id] = 1
            return snapshot
        candidate = self._candidate.get(snapshot.sensor_id)
        self._count[snapshot.sensor_id] = self._count.get(snapshot.sensor_id, 0) + 1 if candidate == desired else 1
        self._candidate[snapshot.sensor_id] = desired
        required = policy.consecutive_successes_required if desired in {SensorState.HEALTHY, SensorState.HEALTHY_IDLE} else policy.consecutive_failures_required
        if desired != previous.state and self._count[snapshot.sensor_id] < required:
            held_state = SensorState.STABILIZING if previous.state in {SensorState.RECOVERING, SensorState.STABILIZING} and desired in {SensorState.HEALTHY, SensorState.HEALTHY_IDLE} else previous.state
            return replace(
                snapshot,
                state=held_state,
                health_score=min(snapshot.health_score, previous.health_score),
                reason=f"Pending sustained validation ({self._count[snapshot.sensor_id]}/{required}): {snapshot.reason}",
            )
        return snapshot


class SensorHealthEvaluator:
    def evaluate(self, raw: SensorHealthSnapshot, policy: SensorHealthPolicy, *, now: datetime | None = None) -> SensorHealthSnapshot:
        now = now or utc_now()
        snapshot = self._validated(raw)
        reasons: list[tuple[int, SensorState, ReasonCode, str, str]] = []
        dimension = {
            "process_health": SensorState.HEALTHY if snapshot.process_alive else SensorState.FAILED,
            "collection_health": SensorState.UNKNOWN,
            "processing_health": SensorState.UNKNOWN,
            "delivery_health": SensorState.UNKNOWN,
            "storage_health": SensorState.UNKNOWN,
            "dependency_health": SensorState.HEALTHY,
            "permission_health": SensorState.UNKNOWN,
            "configuration_health": SensorState.UNKNOWN,
            "rule_health": SensorState.UNKNOWN,
        }

        def issue(priority: int, state: SensorState, code: ReasonCode, message: str, field: str = "") -> None:
            reasons.append((priority, state, code, message, field))
            if field:
                dimension[field] = state

        if not snapshot.process_alive:
            issue(100, SensorState.FAILED, ReasonCode.PROCESS_NOT_RUNNING, "Sensor process is not running; functional coverage is unavailable.", "process_health")
        elif not snapshot.initialized:
            issue(55, SensorState.INITIALIZING, ReasonCode.INITIALIZING, "Sensor process is alive but initialization and readiness are not complete.", "process_health")

        heartbeat_age = _age(snapshot.last_process_heartbeat, now)
        if snapshot.process_alive and (heartbeat_age is None or heartbeat_age > policy.heartbeat_timeout):
            issue(90, SensorState.STALE, ReasonCode.HEARTBEAT_STALE, "Execution-loop heartbeat is stale even though the process is present.", "process_health")

        if snapshot.permission_state in {PermissionState.DENIED, PermissionState.REVOKED, PermissionState.USER_ACTION_REQUIRED}:
            code = ReasonCode.PERMISSION_REVOKED if snapshot.permission_state == PermissionState.REVOKED else ReasonCode.PERMISSION_REQUIRED
            issue(98, SensorState.PERMISSION_BLOCKED, code, "A required macOS permission is not granted; affected coverage cannot be restored automatically.", "permission_health")
        elif snapshot.permission_state == PermissionState.GRANTED:
            dimension["permission_health"] = SensorState.HEALTHY

        required_dependencies = [item for item in snapshot.dependencies if item.required]
        failed_dependencies = [item for item in required_dependencies if item.state in {DependencyState.FAILED, DependencyState.UNAVAILABLE}]
        degraded_dependencies = [item for item in required_dependencies if item.state in {DependencyState.DEGRADED, DependencyState.UNKNOWN}]
        if failed_dependencies:
            names = ", ".join(item.dependency_id for item in failed_dependencies)
            issue(95, SensorState.DEPENDENCY_FAILED, ReasonCode.DEPENDENCY_FAILURE, f"Required dependency unavailable: {names}.", "dependency_health")
        elif degraded_dependencies:
            names = ", ".join(item.dependency_id for item in degraded_dependencies)
            issue(60, SensorState.DEGRADED, ReasonCode.DEPENDENCY_FAILURE, f"Dependency health is incomplete or degraded: {names}.", "dependency_health")

        if snapshot.expected_configuration_hash:
            if not snapshot.configuration_hash:
                issue(92, SensorState.CONFIGURATION_ERROR, ReasonCode.CONFIG_INVALID, "Effective runtime configuration hash is unavailable.", "configuration_health")
            elif snapshot.configuration_hash != snapshot.expected_configuration_hash:
                issue(92, SensorState.CONFIGURATION_ERROR, ReasonCode.CONFIG_UNEXPECTED_CHANGE, "Effective runtime configuration differs from the expected signed configuration.", "configuration_health")
            else:
                dimension["configuration_health"] = SensorState.HEALTHY
        elif snapshot.configuration_hash:
            dimension["configuration_health"] = SensorState.HEALTHY_WITH_WARNINGS

        rules = snapshot.rules
        if rules.failed or rules.invalid or (rules.expected and rules.loaded < rules.expected - rules.disabled):
            issue(78, SensorState.DEGRADED, ReasonCode.RULE_LOAD_FAILURE, f"Ruleset coverage is incomplete ({rules.loaded}/{rules.expected} loaded, {rules.failed + rules.invalid} failed or invalid).", "rule_health")
        elif rules.expected:
            dimension["rule_health"] = SensorState.HEALTHY

        collection_age = _age(snapshot.last_collection_activity, now)
        processing_age = _age(snapshot.last_processing_activity, now)
        delivery_age = _age(snapshot.last_delivery_activity, now)
        persistence_age = _age(snapshot.last_persistence_activity, now)
        if collection_age is not None:
            dimension["collection_health"] = SensorState.HEALTHY if collection_age <= policy.event_stale_timeout else SensorState.STALE
        if processing_age is not None:
            dimension["processing_health"] = SensorState.HEALTHY if processing_age <= policy.processing_stall_timeout else SensorState.STALE
        if delivery_age is not None:
            dimension["delivery_health"] = SensorState.HEALTHY if delivery_age <= policy.delivery_stall_timeout else SensorState.STALE
        if persistence_age is not None:
            dimension["storage_health"] = SensorState.HEALTHY if persistence_age <= policy.persistence_stall_timeout else SensorState.STALE

        if snapshot.queue_depth > 0 and (processing_age is None or processing_age > policy.processing_stall_timeout):
            issue(88, SensorState.IMPAIRED, ReasonCode.PROCESSING_STALL, "Pending events exist but the processing progress heartbeat is stale.", "processing_health")
        if snapshot.metadata.get("delivery_required", True) and snapshot.events_processed_total > snapshot.events_delivered_total and (delivery_age is None or delivery_age > policy.delivery_stall_timeout):
            issue(82, SensorState.IMPAIRED, ReasonCode.DELIVERY_STALL, "Processed telemetry is not progressing to downstream consumers.", "delivery_health")
        if snapshot.metadata.get("persistence_required", True) and snapshot.events_processed_total > snapshot.events_persisted_total and (persistence_age is None or persistence_age > policy.persistence_stall_timeout):
            issue(84, SensorState.IMPAIRED, ReasonCode.PERSISTENCE_STALL, "Processed telemetry is not being persisted within the required window.", "storage_health")

        if collection_age is None or collection_age > policy.maximum_expected_idle_time:
            if snapshot.last_self_test and snapshot.last_self_test.passed:
                issue(10, SensorState.HEALTHY_IDLE, ReasonCode.NO_EVENTS_EXPECTED, "No external events were expected; the latest synthetic pipeline probe passed.", "collection_health")
            elif snapshot.initialized:
                issue(75, SensorState.STALE, ReasonCode.EVENT_STREAM_STALE, "No expected telemetry or successful synthetic pipeline proof is recent enough.", "collection_health")

        utilization = snapshot.queue_utilization
        if utilization >= policy.critical_queue_utilization:
            code = ReasonCode.QUEUE_OVERFLOW if snapshot.events_dropped_total else ReasonCode.QUEUE_BACKPRESSURE
            issue(94, SensorState.IMPAIRED, code, f"Queue utilization is critical at {utilization:.0%}.", "processing_health")
        elif utilization >= policy.degraded_queue_utilization and snapshot.backpressure_duration_seconds >= policy.backpressure_sustain_seconds:
            issue(80, SensorState.BACKPRESSURED, ReasonCode.QUEUE_BACKPRESSURE, f"Queue utilization has remained at {utilization:.0%} for {snapshot.backpressure_duration_seconds:.0f} seconds.", "processing_health")
        elif utilization >= policy.elevated_queue_utilization:
            issue(35, SensorState.HEALTHY_WITH_WARNINGS, ReasonCode.QUEUE_BACKPRESSURE, f"Queue utilization is elevated at {utilization:.0%}; no sustained loss is proven.", "processing_health")

        calculated_drop_rate = snapshot.drop_rate
        if calculated_drop_rate is None and snapshot.events_received_total:
            calculated_drop_rate = snapshot.events_dropped_total / snapshot.events_received_total
        if snapshot.events_dropped_total and calculated_drop_rate is not None and calculated_drop_rate > policy.max_drop_rate:
            issue(86, SensorState.DEGRADED, ReasonCode.EVENT_LOSS, f"Unintended event loss is {calculated_drop_rate:.2%}; intentional filtering is accounted separately.", "collection_health")
        if snapshot.processing_latency_ms is not None and snapshot.processing_latency_ms > policy.max_processing_latency_ms:
            issue(68, SensorState.DEGRADED, ReasonCode.PROCESSING_STALL, f"Processing latency is {snapshot.processing_latency_ms:.0f} ms, above the sensor policy SLO.", "processing_health")

        resources = snapshot.resources
        if resources.database_latency_ms is not None and resources.database_latency_ms > policy.max_database_latency_ms:
            issue(65, SensorState.DEGRADED, ReasonCode.DATABASE_LATENCY, "Evidence database latency is above the configured operational SLO.", "storage_health")
        if (resources.free_disk_bytes is not None and resources.free_disk_bytes < policy.min_free_disk_bytes) or (resources.free_disk_percent is not None and resources.free_disk_percent < policy.min_free_disk_percent):
            issue(87, SensorState.DEGRADED, ReasonCode.DISK_PRESSURE, "Available disk capacity is below the configured evidence reserve.", "storage_health")
        if resources.descriptor_limit and resources.open_descriptors is not None:
            descriptor_ratio = resources.open_descriptors / resources.descriptor_limit
            if descriptor_ratio >= policy.descriptor_critical_ratio:
                issue(88, SensorState.IMPAIRED, ReasonCode.DESCRIPTOR_PRESSURE, f"File descriptor utilization is critical at {descriptor_ratio:.0%}.")
            elif descriptor_ratio >= policy.descriptor_degraded_ratio:
                issue(66, SensorState.DEGRADED, ReasonCode.DESCRIPTOR_PRESSURE, f"File descriptor utilization is elevated at {descriptor_ratio:.0%}.")
        if resources.rss_growth_bytes is not None and resources.rss_growth_bytes > 256 * 1024 * 1024:
            issue(55, SensorState.DEGRADED, ReasonCode.MEMORY_GROWTH, "Sustained RSS growth requires investigation; a fixed memory threshold alone was not used.")

        if snapshot.restart_count > policy.restart_budget_count:
            issue(99, SensorState.FAILED, ReasonCode.RESTART_LOOP, "Restart budget is exhausted; automatic restarts must stop and evidence must be retained.")
        if snapshot.metadata.get("duplicate_instances", 0) > 1:
            issue(97, SensorState.IMPAIRED, ReasonCode.DUPLICATE_INSTANCE, "Multiple singleton sensor instances were observed; automatic termination was not attempted.")
        if snapshot.last_self_test and not snapshot.last_self_test.passed:
            issue(83, SensorState.DEGRADED, ReasonCode.SELF_TEST_FAILED, f"Functional self-test failed: {snapshot.last_self_test.reason}")
        if snapshot.fallback_mode:
            issue(72, SensorState.DEGRADED, ReasonCode.FALLBACK_MODE_ACTIVE, f"Fallback mode is active: {snapshot.fallback_mode}. Equivalent primary coverage is not claimed.")

        if not reasons:
            evidence_present = all((snapshot.last_process_heartbeat, snapshot.initialized)) and any((snapshot.last_collection_activity, snapshot.last_self_test, snapshot.events_received_total))
            if evidence_present:
                reasons.append((0, SensorState.HEALTHY, ReasonCode.NONE, "Sensor is initialized and its functional telemetry path is within policy.", ""))
            else:
                reasons.append((45, SensorState.UNKNOWN, ReasonCode.UNKNOWN_DEGRADATION, "Functional telemetry evidence is incomplete; healthy status is withheld.", ""))

        priority, state, code, reason, _field = max(reasons, key=lambda item: item[0])
        score = min(_state_rank(state), self._score(snapshot, reasons))
        dimensions = {key: (SensorState.HEALTHY if value == SensorState.UNKNOWN and state in {SensorState.HEALTHY, SensorState.HEALTHY_IDLE} else value) for key, value in dimension.items()}
        return replace(snapshot, state=state, health_score=score, reason_code=code, reason=reason, sampled_at=now, **dimensions)

    @staticmethod
    def _score(snapshot: SensorHealthSnapshot, reasons: list[tuple[int, SensorState, ReasonCode, str, str]]) -> int:
        score = 100
        penalties = {
            SensorState.HEALTHY_WITH_WARNINGS: 8, SensorState.HIGH_LOAD: 12,
            SensorState.DEGRADED: 25, SensorState.BACKPRESSURED: 35,
            SensorState.STALE: 40, SensorState.IMPAIRED: 55,
            SensorState.PERMISSION_BLOCKED: 70, SensorState.CONFIGURATION_ERROR: 70,
            SensorState.DEPENDENCY_FAILED: 70, SensorState.FAILED: 100,
            SensorState.UNAVAILABLE: 100, SensorState.UNKNOWN: 60,
            SensorState.INITIALIZING: 50, SensorState.HEALTHY_IDLE: 0,
        }
        for state in {item[1] for item in reasons}:
            score -= penalties.get(state, 0)
        if snapshot.events_dropped_total:
            score -= min(20, snapshot.events_dropped_total)
        return max(0, min(100, score))

    @staticmethod
    def _validated(snapshot: SensorHealthSnapshot) -> SensorHealthSnapshot:
        if not snapshot.sensor_id or len(snapshot.sensor_id) > 64:
            raise ValueError("sensor_id is missing or too long")
        numeric = (
            snapshot.events_received_total, snapshot.events_processed_total,
            snapshot.events_delivered_total, snapshot.events_persisted_total,
            snapshot.events_dropped_total, snapshot.events_failed_total,
            snapshot.queue_depth, snapshot.queue_capacity, snapshot.restart_count,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("sensor counters and queue metrics cannot be negative")
        if snapshot.queue_capacity and snapshot.queue_depth > snapshot.queue_capacity * 100:
            raise ValueError("queue depth exceeds the bounded health payload range")
        if len(snapshot.metadata) > 128:
            raise ValueError("sensor health metadata exceeds the bounded field count")
        return snapshot


def capability_coverage(descriptor: SensorDescriptor, snapshot: SensorHealthSnapshot) -> tuple[CapabilityHealth, ...]:
    declared = snapshot.capabilities
    if not declared:
        declared = tuple(CapabilityHealth(item, CoverageLevel.UNKNOWN, snapshot.reason, snapshot.fallback_mode) for item in descriptor.capabilities)
    if snapshot.state in FAILURE_STATES:
        maximum = CoverageLevel.NONE
    elif snapshot.state in DEGRADED_STATES or snapshot.state in {SensorState.HIGH_LOAD, SensorState.RECOVERING, SensorState.STABILIZING}:
        maximum = CoverageLevel.PARTIAL
    elif snapshot.state == SensorState.MAINTENANCE:
        maximum = CoverageLevel.UNKNOWN
    else:
        maximum = CoverageLevel.FULL
    rank = {CoverageLevel.NONE: 0, CoverageLevel.UNKNOWN: 1, CoverageLevel.LIMITED: 2, CoverageLevel.PARTIAL: 3, CoverageLevel.FULL: 4}
    output = []
    for capability in declared:
        effective = capability.coverage if rank[capability.coverage] <= rank[maximum] else maximum
        reason = capability.reason
        if effective != capability.coverage:
            reason = f"Effective coverage is capped by {snapshot.state.value}: {snapshot.reason}"
        output.append(CapabilityHealth(capability.capability_id, effective, reason, capability.fallback, capability.confidence))
    return tuple(output)


def build_platform_report(pairs: Iterable[tuple[SensorDescriptor, SensorHealthSnapshot]], *, manager_health: dict | None = None) -> PlatformHealthReport:
    pairs = tuple(pairs)
    required = [(descriptor, snapshot) for descriptor, snapshot in pairs if descriptor.expected and descriptor.enabled]
    failed_critical = any(descriptor.criticality == Criticality.CRITICAL and snapshot.state in FAILURE_STATES for descriptor, snapshot in required)
    degraded_critical = any(descriptor.criticality == Criticality.CRITICAL and snapshot.state in DEGRADED_STATES for descriptor, snapshot in required)
    failed_any = any(snapshot.state in FAILURE_STATES for _descriptor, snapshot in required)
    degraded_any = any(snapshot.state in DEGRADED_STATES for _descriptor, snapshot in required)
    unknown_any = any(snapshot.state in {SensorState.UNKNOWN, SensorState.INITIALIZING} for _descriptor, snapshot in required)
    maintenance = bool(required) and all(snapshot.state == SensorState.MAINTENANCE for _descriptor, snapshot in required)
    if maintenance:
        overall = PlatformState.MAINTENANCE
    elif failed_critical:
        overall = PlatformState.FAILED
    elif degraded_critical or (failed_any and len(required) > 1):
        overall = PlatformState.SEVERELY_DEGRADED
    elif failed_any or degraded_any:
        overall = PlatformState.DEGRADED
    elif unknown_any or any(snapshot.state == SensorState.HEALTHY_WITH_WARNINGS for _descriptor, snapshot in required):
        overall = PlatformState.HEALTHY_WITH_WARNINGS if not unknown_any else PlatformState.UNKNOWN
    else:
        overall = PlatformState.HEALTHY

    coverage_by_id: dict[str, CapabilityHealth] = {}
    coverage_rank = {CoverageLevel.NONE: 0, CoverageLevel.UNKNOWN: 1, CoverageLevel.LIMITED: 2, CoverageLevel.PARTIAL: 3, CoverageLevel.FULL: 4}
    for descriptor, snapshot in pairs:
        for capability in capability_coverage(descriptor, snapshot):
            prior = coverage_by_id.get(capability.capability_id)
            if prior is None or coverage_rank[capability.coverage] < coverage_rank[prior.coverage]:
                coverage_by_id[capability.capability_id] = capability

    roots: dict[str, list[str]] = {}
    for descriptor, snapshot in required:
        for dependency in snapshot.dependencies:
            if dependency.required and dependency.state in {DependencyState.FAILED, DependencyState.UNAVAILABLE}:
                roots.setdefault(dependency.dependency_id, []).append(descriptor.display_name)
    root_causes = tuple({"dependency": dependency, "affected_sensors": names, "affected_count": len(names)} for dependency, names in sorted(roots.items()))
    healthy_states = {SensorState.HEALTHY, SensorState.HEALTHY_IDLE, SensorState.HEALTHY_WITH_WARNINGS}
    return PlatformHealthReport(
        overall_health=overall,
        generated_at=utc_now(),
        sensors=tuple(snapshot for _descriptor, snapshot in pairs),
        coverage=tuple(sorted(coverage_by_id.values(), key=lambda item: item.capability_id)),
        required_healthy=sum(snapshot.state in healthy_states for _descriptor, snapshot in required),
        required_total=len(required),
        degraded_count=sum(snapshot.state in DEGRADED_STATES for _descriptor, snapshot in required),
        failed_count=sum(snapshot.state in FAILURE_STATES for _descriptor, snapshot in required),
        active_recoveries=sum(snapshot.state in {SensorState.RECOVERING, SensorState.STABILIZING} for _descriptor, snapshot in required),
        root_causes=root_causes,
        manager_health=manager_health or {},
    )


__all__ = ["HysteresisTracker", "SensorHealthEvaluator", "build_platform_report", "capability_coverage"]
