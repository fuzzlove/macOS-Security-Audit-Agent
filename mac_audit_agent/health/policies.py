"""Validated, sensor-specific reliability policy with conservative defaults."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class SensorHealthPolicy:
    heartbeat_timeout: float = 180.0
    event_stale_timeout: float = 300.0
    maximum_expected_idle_time: float = 900.0
    processing_stall_timeout: float = 120.0
    delivery_stall_timeout: float = 180.0
    persistence_stall_timeout: float = 180.0
    elevated_queue_utilization: float = 0.50
    degraded_queue_utilization: float = 0.75
    critical_queue_utilization: float = 0.90
    backpressure_sustain_seconds: float = 30.0
    max_drop_rate: float = 0.01
    max_processing_latency_ms: float = 2_000.0
    max_database_latency_ms: float = 750.0
    min_free_disk_bytes: int = 1_073_741_824
    min_free_disk_percent: float = 5.0
    descriptor_observe_ratio: float = 0.70
    descriptor_degraded_ratio: float = 0.85
    descriptor_critical_ratio: float = 0.95
    consecutive_failures_required: int = 3
    consecutive_successes_required: int = 5
    restart_budget_count: int = 3
    restart_budget_window_seconds: int = 300
    stabilization_seconds: int = 30
    provider_timeout_seconds: float = 5.0
    self_test_timeout_seconds: float = 10.0
    lightweight_self_test_interval: int = 900
    extended_self_test_interval: int = 86_400
    availability_degradation_budget_seconds: int = 900

    def __post_init__(self) -> None:
        positive = (
            "heartbeat_timeout", "event_stale_timeout", "maximum_expected_idle_time",
            "processing_stall_timeout", "delivery_stall_timeout", "persistence_stall_timeout",
            "backpressure_sustain_seconds", "max_processing_latency_ms", "max_database_latency_ms",
            "provider_timeout_seconds", "self_test_timeout_seconds",
        )
        for name in positive:
            if float(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")
        ordered = (self.elevated_queue_utilization, self.degraded_queue_utilization, self.critical_queue_utilization)
        if not (0 < ordered[0] < ordered[1] < ordered[2] <= 1):
            raise ValueError("queue thresholds must be ordered fractions in (0, 1]")
        descriptor = (self.descriptor_observe_ratio, self.descriptor_degraded_ratio, self.descriptor_critical_ratio)
        if not (0 < descriptor[0] < descriptor[1] < descriptor[2] <= 1):
            raise ValueError("descriptor thresholds must be ordered fractions in (0, 1]")
        if not 0 <= self.max_drop_rate <= 1:
            raise ValueError("max_drop_rate must be a fraction")
        if min(self.consecutive_failures_required, self.consecutive_successes_required, self.restart_budget_count) < 1:
            raise ValueError("hysteresis and restart-budget counts must be positive")


DEFAULT_POLICY = SensorHealthPolicy()

SENSOR_POLICY_OVERRIDES: dict[str, SensorHealthPolicy] = {
    "endpoint_security": replace(DEFAULT_POLICY, heartbeat_timeout=90, event_stale_timeout=180, maximum_expected_idle_time=300, max_drop_rate=0.0),
    "ransomware_monitor": replace(DEFAULT_POLICY, heartbeat_timeout=90, event_stale_timeout=180, maximum_expected_idle_time=300, max_drop_rate=0.0),
    "system_monitor": replace(DEFAULT_POLICY, heartbeat_timeout=180, maximum_expected_idle_time=900),
    "behavioral_telemetry": replace(DEFAULT_POLICY, heartbeat_timeout=600, event_stale_timeout=900, maximum_expected_idle_time=3_600),
    "malware_definitions": replace(DEFAULT_POLICY, heartbeat_timeout=3_600, event_stale_timeout=86_400, maximum_expected_idle_time=86_400),
    "user_notifier": replace(DEFAULT_POLICY, heartbeat_timeout=180, event_stale_timeout=3_600, maximum_expected_idle_time=3_600),
    "sensor_health_manager": replace(DEFAULT_POLICY, heartbeat_timeout=180, event_stale_timeout=300),
}


def policy_for(sensor_id: str) -> SensorHealthPolicy:
    return SENSOR_POLICY_OVERRIDES.get(sensor_id, DEFAULT_POLICY)


__all__ = ["DEFAULT_POLICY", "SENSOR_POLICY_OVERRIDES", "SensorHealthPolicy", "policy_for"]
