from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


FEATURE_SCHEMA_VERSION = "1.0"
BEHAVIOR_MODEL_VERSION = "robust-statistics-1.0"


class ActivityDimension(str, Enum):
    PROCESS = "PROCESS_ACTIVITY"
    APPLICATION = "APPLICATION_ACTIVITY"
    NETWORK = "NETWORK_ACTIVITY"
    DNS = "DNS_ACTIVITY"
    FILESYSTEM = "FILESYSTEM_ACTIVITY"
    PERSISTENCE = "PERSISTENCE_ACTIVITY"
    AUTHENTICATION = "AUTHENTICATION_ACTIVITY"
    PRIVILEGE = "PRIVILEGE_ACTIVITY"
    SECURITY_CONFIGURATION = "SECURITY_CONFIGURATION_ACTIVITY"
    SOFTWARE = "SOFTWARE_INSTALLATION_ACTIVITY"
    EXTERNAL_DEVICE = "EXTERNAL_DEVICE_ACTIVITY"
    SENSOR = "SENSOR_SECURITY_TOOL_ACTIVITY"


class BaselineState(str, Enum):
    LEARNING = "LEARNING"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    ESTABLISHED = "ESTABLISHED"
    MATURE = "MATURE"


class AnalyticsAvailability(str, Enum):
    VALID = "VALID"
    REDUCED = "REDUCED"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class AnomalyDisposition(str, Enum):
    NEW = "NEW"
    EXPECTED = "EXPECTED_BEHAVIOR"
    INVESTIGATE = "INVESTIGATE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED = "CONFIRMED_INCIDENT"


@dataclass(frozen=True)
class NormalizedTelemetryEvent:
    event_id: str
    timestamp: str
    monotonic_timestamp: float
    host_ref: str
    user_ref: str
    user_class: str
    dimension: ActivityDimension
    event_name: str
    features: dict[str, float]
    entity_keys: dict[str, str] = field(default_factory=dict)
    security_context: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    sensor_id: str = "system_monitor"
    coverage: AnalyticsAvailability = AnalyticsAvailability.VALID
    baseline_training_eligible: bool = True
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.event_id or not self.timestamp or not self.host_ref:
            raise ValueError("normalized telemetry requires event, time, and host references")
        if len(self.features) > 64 or any(not isinstance(value, (int, float)) for value in self.features.values()):
            raise ValueError("telemetry features must be a bounded numeric mapping")
        if any(value < 0 or value != value or value == float("inf") for value in self.features.values()):
            raise ValueError("telemetry feature values must be finite and non-negative")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["dimension"] = self.dimension.value
        payload["coverage"] = self.coverage.value
        return payload


@dataclass
class TelemetryBucket:
    bucket_start: str
    bucket_end: str
    host_ref: str
    user_ref: str
    time_cohort: str
    context_cohort: str = "STEADY_STATE"
    feature_values: dict[str, float | None] = field(default_factory=dict)
    dimension_values: dict[str, float | None] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    entity_sets: dict[str, list[str]] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    training_eligible: bool = True
    event_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeatureBaseline:
    baseline_id: str
    host_ref: str
    user_ref: str
    feature_name: str
    time_cohort: str
    context_cohort: str
    median_value: float
    mad_value: float
    p05: float
    p25: float
    p50: float
    p75: float
    p95: float
    sample_count: int
    confidence: float
    state: BaselineState
    version: int
    updated_at: str

    @property
    def normal_low(self) -> float:
        return max(0.0, self.p05)

    @property
    def normal_high(self) -> float:
        return max(self.normal_low, self.p95)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["normal_low"] = self.normal_low
        payload["normal_high"] = self.normal_high
        return payload


@dataclass
class BehavioralAnomaly:
    anomaly_id: str
    timestamp: str
    host_ref: str
    user_ref: str
    dimension: str
    anomaly_score: int
    security_severity: str
    detection_confidence: float
    baseline_value: float | None
    observed_value: float | None
    normal_low: float | None
    normal_high: float | None
    reason_codes: list[str]
    reasons: list[str]
    related_entities: dict[str, str]
    evidence_refs: list[str]
    sensor_coverage: dict[str, str]
    baseline_version: int
    active_behavior_policy: str
    baseline_training_eligible: bool = False
    behavior_model_version: str = BEHAVIOR_MODEL_VERSION
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    incident_id: str = ""
    disposition: str = AnomalyDisposition.NEW.value
    recommendation: str = "Review the related canonical evidence and validate whether the activity was expected."
    explanation: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BehavioralIncident:
    incident_id: str
    first_seen: str
    last_seen: str
    host_ref: str
    user_ref: str
    primary_entity: str
    anomaly_ids: list[str]
    reason_codes: list[str]
    anomaly_score: int
    security_severity: str
    detection_confidence: float
    evidence_refs: list[str]
    status: str = "NEW"
    alert_event_id: str = ""
    flight_recorder_snapshot_id: str = ""
    occurrence_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "ActivityDimension", "AnalyticsAvailability", "AnomalyDisposition", "BaselineState",
    "BehavioralAnomaly", "BehavioralIncident", "FeatureBaseline", "NormalizedTelemetryEvent",
    "TelemetryBucket", "BEHAVIOR_MODEL_VERSION", "FEATURE_SCHEMA_VERSION", "utc_now_iso",
]
