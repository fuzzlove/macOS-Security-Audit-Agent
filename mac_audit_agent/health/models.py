"""Typed contracts for functional sensor health and security coverage.

These models intentionally do not represent launchd/process supervision.  The
service watchdog owns liveness and restart execution; this package proves that
an alive component is delivering the security capability it advertises.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from mac_audit_agent.compat.enum import StrEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SensorState(StrEnum):
    UNKNOWN = "UNKNOWN"
    INITIALIZING = "INITIALIZING"
    HEALTHY = "HEALTHY"
    HEALTHY_IDLE = "HEALTHY_IDLE"
    HEALTHY_WITH_WARNINGS = "HEALTHY_WITH_WARNINGS"
    DEGRADED = "DEGRADED"
    IMPAIRED = "IMPAIRED"
    RECOVERING = "RECOVERING"
    STABILIZING = "STABILIZING"
    STALE = "STALE"
    FAILED = "FAILED"
    DISABLED = "DISABLED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    PERMISSION_BLOCKED = "PERMISSION_BLOCKED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    BACKPRESSURED = "BACKPRESSURED"
    HIGH_LOAD = "HIGH_LOAD"
    MAINTENANCE = "MAINTENANCE"


class PlatformState(StrEnum):
    HEALTHY = "HEALTHY"
    HEALTHY_WITH_WARNINGS = "HEALTHY_WITH_WARNINGS"
    DEGRADED = "DEGRADED"
    SEVERELY_DEGRADED = "SEVERELY_DEGRADED"
    FAILED = "FAILED"
    MAINTENANCE = "MAINTENANCE"
    UNKNOWN = "UNKNOWN"


class Criticality(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def weight(self) -> int:
        return {self.CRITICAL: 5, self.HIGH: 4, self.MEDIUM: 3, self.LOW: 2, self.INFORMATIONAL: 1}[self]


class CoverageLevel(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    LIMITED = "LIMITED"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class DependencyState(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PermissionState(StrEnum):
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"
    PENDING = "PENDING"
    USER_ACTION_REQUIRED = "USER_ACTION_REQUIRED"


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ReasonCode(StrEnum):
    NONE = "NONE"
    INITIALIZING = "INITIALIZING"
    PROCESS_NOT_RUNNING = "PROCESS_NOT_RUNNING"
    HEARTBEAT_STALE = "HEARTBEAT_STALE"
    EVENT_STREAM_STALE = "EVENT_STREAM_STALE"
    NO_EVENTS_EXPECTED = "NO_EVENTS_EXPECTED"
    TELEMETRY_SOURCE_UNAVAILABLE = "TELEMETRY_SOURCE_UNAVAILABLE"
    QUEUE_BACKPRESSURE = "QUEUE_BACKPRESSURE"
    QUEUE_OVERFLOW = "QUEUE_OVERFLOW"
    EVENT_LOSS = "EVENT_LOSS"
    PROCESSING_STALL = "PROCESSING_STALL"
    DELIVERY_STALL = "DELIVERY_STALL"
    PERSISTENCE_STALL = "PERSISTENCE_STALL"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    DATABASE_LATENCY = "DATABASE_LATENCY"
    IPC_DISCONNECTED = "IPC_DISCONNECTED"
    HELPER_UNAVAILABLE = "HELPER_UNAVAILABLE"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"
    PERMISSION_REQUIRED = "PERMISSION_REQUIRED"
    ENTITLEMENT_MISSING = "ENTITLEMENT_MISSING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    RULE_LOAD_FAILURE = "RULE_LOAD_FAILURE"
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_UNEXPECTED_CHANGE = "CONFIG_UNEXPECTED_CHANGE"
    CONFIG_ROLLBACK_DETECTED = "CONFIG_ROLLBACK_DETECTED"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    MEMORY_PRESSURE = "MEMORY_PRESSURE"
    MEMORY_GROWTH = "MEMORY_GROWTH"
    DESCRIPTOR_PRESSURE = "DESCRIPTOR_PRESSURE"
    DISK_PRESSURE = "DISK_PRESSURE"
    SELF_TEST_FAILED = "SELF_TEST_FAILED"
    SELF_TEST_TIMEOUT = "SELF_TEST_TIMEOUT"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    DEPENDENCY_TIMEOUT = "DEPENDENCY_TIMEOUT"
    RESTART_LOOP = "RESTART_LOOP"
    DUPLICATE_INSTANCE = "DUPLICATE_INSTANCE"
    PROCESSING_EVENT_FAILURE = "PROCESSING_EVENT_FAILURE"
    HEALTH_PROVIDER_TIMEOUT = "HEALTH_PROVIDER_TIMEOUT"
    HEALTH_PROVIDER_INVALID = "HEALTH_PROVIDER_INVALID"
    FALLBACK_MODE_ACTIVE = "FALLBACK_MODE_ACTIVE"
    RECOVERY_IN_PROGRESS = "RECOVERY_IN_PROGRESS"
    RECOVERY_VALIDATION_FAILED = "RECOVERY_VALIDATION_FAILED"
    MAINTENANCE_ACTIVE = "MAINTENANCE_ACTIVE"
    CLOCK_DISCONTINUITY = "CLOCK_DISCONTINUITY"
    UNKNOWN_DEGRADATION = "UNKNOWN_DEGRADATION"


class RecoveryLevel(StrEnum):
    OBSERVE = "OBSERVE"
    RETRY = "RETRY"
    RECONNECT = "RECONNECT"
    REINITIALIZE = "REINITIALIZE"
    RESTART_WORKER = "RESTART_WORKER"
    RESTART_SENSOR = "RESTART_SENSOR"
    REQUEST_WATCHDOG = "REQUEST_WATCHDOG"
    OPERATOR_REQUIRED = "OPERATOR_REQUIRED"


@dataclass(frozen=True)
class SensorDependency:
    dependency_id: str
    required: bool = True
    state: DependencyState = DependencyState.UNKNOWN
    reason: str = ""
    latency_ms: float | None = None
    last_checked: datetime | None = None
    affected_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityHealth:
    capability_id: str
    coverage: CoverageLevel = CoverageLevel.UNKNOWN
    reason: str = ""
    fallback: str = ""
    confidence: str = "unknown"


@dataclass(frozen=True)
class RuleHealth:
    expected: int = 0
    loaded: int = 0
    failed: int = 0
    disabled: int = 0
    expired: int = 0
    invalid: int = 0
    version: str = ""
    ruleset_hash: str = ""
    last_reload: datetime | None = None


@dataclass(frozen=True)
class ResourceMetrics:
    cpu_percent: float | None = None
    rss_bytes: int | None = None
    rss_growth_bytes: int | None = None
    thread_count: int | None = None
    open_descriptors: int | None = None
    descriptor_limit: int | None = None
    free_disk_bytes: int | None = None
    free_disk_percent: float | None = None
    database_latency_ms: float | None = None
    ipc_latency_ms: float | None = None


@dataclass(frozen=True)
class SelfTestResult:
    passed: bool
    test_id: str
    reason: str = ""
    latency_ms: float | None = None
    canary_id: str = ""
    stages: tuple[str, ...] = ()
    completed_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class RecoveryReason:
    reason_code: ReasonCode
    detail: str
    requested_level: RecoveryLevel = RecoveryLevel.OBSERVE


@dataclass(frozen=True)
class RecoveryResult:
    attempted: bool
    succeeded: bool
    action: RecoveryLevel
    detail: str = ""
    requires_operator: bool = False
    verification_required: bool = True


@dataclass(frozen=True)
class SensorDescriptor:
    sensor_id: str
    display_name: str
    criticality: Criticality
    expected: bool = True
    enabled: bool = True
    singleton: bool = True
    capabilities: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    failure_domain: str = "general"


@dataclass
class SensorHealthSnapshot:
    sensor_id: str
    sensor_version: str = "unknown"
    instance_uuid: str = ""
    pid: int | None = None
    process_alive: bool = False
    initialized: bool = False
    state: SensorState = SensorState.UNKNOWN
    health_score: int = 0
    reason_code: ReasonCode = ReasonCode.NONE
    reason: str = "Insufficient functional-health evidence."
    process_health: SensorState = SensorState.UNKNOWN
    collection_health: SensorState = SensorState.UNKNOWN
    processing_health: SensorState = SensorState.UNKNOWN
    delivery_health: SensorState = SensorState.UNKNOWN
    storage_health: SensorState = SensorState.UNKNOWN
    dependency_health: SensorState = SensorState.UNKNOWN
    permission_health: SensorState = SensorState.UNKNOWN
    configuration_health: SensorState = SensorState.UNKNOWN
    rule_health: SensorState = SensorState.UNKNOWN
    last_process_heartbeat: datetime | None = None
    last_collection_activity: datetime | None = None
    last_processing_activity: datetime | None = None
    last_delivery_activity: datetime | None = None
    last_persistence_activity: datetime | None = None
    events_received_total: int = 0
    events_processed_total: int = 0
    events_delivered_total: int = 0
    events_persisted_total: int = 0
    events_ignored_total: int = 0
    events_filtered_total: int = 0
    events_dropped_total: int = 0
    events_failed_total: int = 0
    events_duplicate_total: int = 0
    events_rejected_total: int = 0
    processing_latency_ms: float | None = None
    queue_depth: int = 0
    queue_capacity: int = 0
    oldest_event_age_seconds: float | None = None
    ingestion_rate: float | None = None
    processing_rate: float | None = None
    drop_rate: float | None = None
    peak_queue_depth: int = 0
    average_queue_depth: float = 0.0
    backpressure_duration_seconds: float = 0.0
    error_count: int = 0
    consecutive_error_count: int = 0
    restart_count: int = 0
    worker_sequence: int = 0
    permission_state: PermissionState = PermissionState.UNKNOWN
    configuration_hash: str = ""
    expected_configuration_hash: str = ""
    dependencies: tuple[SensorDependency, ...] = ()
    capabilities: tuple[CapabilityHealth, ...] = ()
    rules: RuleHealth = field(default_factory=RuleHealth)
    resources: ResourceMetrics = field(default_factory=ResourceMetrics)
    last_self_test: SelfTestResult | None = None
    fallback_mode: str = ""
    lost_capabilities: tuple[str, ...] = ()
    retained_capabilities: tuple[str, ...] = ()
    operator_action_required: bool = False
    remediation: str = ""
    sampled_at: datetime = field(default_factory=utc_now)
    monotonic_sample: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def queue_utilization(self) -> float:
        if self.queue_capacity <= 0:
            return 0.0
        return min(1.0, max(0.0, self.queue_depth / self.queue_capacity))

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, datetime):
                return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if isinstance(value, StrEnum):
                return value.value
            if isinstance(value, dict):
                return {str(key): convert(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [convert(item) for item in value]
            return value

        return convert(asdict(self))


@dataclass(frozen=True)
class HealthTransition:
    event_type: str
    sensor_id: str
    timestamp: datetime
    previous_state: SensorState
    current_state: SensorState
    reason_code: ReasonCode
    reason: str
    severity: str
    affected_capabilities: tuple[str, ...] = ()
    metrics: dict[str, Any] = field(default_factory=dict)
    automatic_recovery_attempted: bool = False
    root_cause_dependency: str = ""


@dataclass(frozen=True)
class PlatformHealthReport:
    overall_health: PlatformState
    generated_at: datetime
    sensors: tuple[SensorHealthSnapshot, ...]
    coverage: tuple[CapabilityHealth, ...]
    required_healthy: int
    required_total: int
    degraded_count: int
    failed_count: int
    active_recoveries: int
    root_causes: tuple[dict[str, Any], ...] = ()
    manager_health: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "overall_health": self.overall_health.value,
            "generated_at": self.generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "required_sensors_healthy": self.required_healthy,
            "required_sensors_total": self.required_total,
            "degraded_sensors": self.degraded_count,
            "failed_sensors": self.failed_count,
            "active_recovery_actions": self.active_recoveries,
            "coverage": [asdict(item) | {"coverage": item.coverage.value} for item in self.coverage],
            "root_causes": list(self.root_causes),
            "manager_health": dict(self.manager_health),
            "sensors": [item.to_dict() for item in self.sensors],
        }


@runtime_checkable
class SensorHealthProvider(Protocol):
    def sensor_id(self) -> str: ...

    def health_snapshot(self) -> SensorHealthSnapshot: ...

    def dependencies(self) -> list[SensorDependency]: ...

    def perform_self_test(self) -> SelfTestResult: ...

    def recover(self, reason: RecoveryReason) -> RecoveryResult: ...


__all__ = [name for name in globals() if not name.startswith("_")]
