"""Explicit development-only functional health fault injection."""

from __future__ import annotations

from dataclasses import replace

from .models import (
    DependencyState, PermissionState, ResourceMetrics, RuleHealth,
    SensorDependency, SensorHealthSnapshot,
)


SUPPORTED_FAULTS = {
    "stale_heartbeat", "queue_saturation", "ipc_failure", "permission_loss",
    "database_timeout", "rule_load_failure", "dropped_events", "processing_stall",
    "memory_pressure", "duplicate_instance",
}


class FaultInjector:
    def __init__(self, faults: dict[str, set[str]] | None = None, *, enabled: bool = False, environment: str = "production") -> None:
        if enabled and environment != "development":
            raise PermissionError("fault injection is available only in an explicit development environment")
        self.enabled = enabled
        self.environment = environment
        self.faults = faults or {}
        unknown = {fault for values in self.faults.values() for fault in values if fault not in SUPPORTED_FAULTS}
        if unknown:
            raise ValueError(f"unsupported fault injection: {sorted(unknown)}")

    def apply(self, snapshot: SensorHealthSnapshot) -> SensorHealthSnapshot:
        if not self.enabled:
            return snapshot
        faults = self.faults.get(snapshot.sensor_id, set())
        result = snapshot
        if "stale_heartbeat" in faults:
            result = replace(result, last_process_heartbeat=None)
        if "queue_saturation" in faults:
            capacity = result.queue_capacity or 100
            result = replace(result, queue_capacity=capacity, queue_depth=capacity, backpressure_duration_seconds=60)
        if "ipc_failure" in faults:
            result = replace(result, dependencies=result.dependencies + (SensorDependency("privileged_helper", True, DependencyState.FAILED, "development fault injection"),))
        if "permission_loss" in faults:
            result = replace(result, permission_state=PermissionState.REVOKED)
        if "database_timeout" in faults:
            result = replace(result, dependencies=result.dependencies + (SensorDependency("sqlite", True, DependencyState.FAILED, "development fault injection timeout"),))
        if "rule_load_failure" in faults:
            result = replace(result, rules=RuleHealth(expected=max(1, result.rules.expected), loaded=0, failed=max(1, result.rules.expected)))
        if "dropped_events" in faults:
            result = replace(result, events_received_total=max(100, result.events_received_total), events_dropped_total=max(5, result.events_dropped_total))
        if "processing_stall" in faults:
            result = replace(result, queue_capacity=max(100, result.queue_capacity), queue_depth=max(1, result.queue_depth), last_processing_activity=None)
        if "memory_pressure" in faults:
            result = replace(result, resources=replace(result.resources, rss_growth_bytes=512 * 1024 * 1024))
        if "duplicate_instance" in faults:
            result = replace(result, metadata={**result.metadata, "duplicate_instances": 2})
        return replace(result, metadata={**result.metadata, "development_faults": sorted(faults)})


__all__ = ["FaultInjector", "SUPPORTED_FAULTS"]
