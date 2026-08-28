from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    UNKNOWN = "AUTHORIZATION_UNKNOWN"
    EXPIRED = "AUTHORIZATION_EXPIRED"
    SCOPE_MISMATCH = "AUTHORIZATION_SCOPE_MISMATCH"
    SIGNATURE_INVALID = "AUTHORIZATION_SIGNATURE_INVALID"


class SensorMode(str, Enum):
    FULLY_OPERATIONAL = "FULLY_OPERATIONAL"
    DEGRADED = "DEGRADED"
    OBSERVATION_ONLY = "OBSERVATION_ONLY"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    SENSOR_OFFLINE = "SENSOR_OFFLINE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class PolicyProfile(str, Enum):
    STANDARD = "STANDARD"
    ENTERPRISE = "ENTERPRISE"
    HIGH_ASSURANCE = "HIGH_ASSURANCE"


@dataclass(frozen=True)
class SecurityControlState:
    control_id: str
    category: str
    collected_at_utc: datetime
    normalized_value: Mapping[str, Any]
    source: str
    confidence: float
    collection_status: str
    collection_error_code: str | None = None
    raw_evidence_digest: str | None = None


@dataclass(frozen=True)
class ActorIdentity:
    effective_uid: int | None = None
    real_uid: int | None = None
    username: str = ""
    audit_session_id: str = ""
    remote_session: bool | None = None


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int | None = None
    parent_pid: int | None = None
    path: str = ""
    parent_path: str = ""
    arguments: tuple[str, ...] = ()
    executable_sha256: str = ""
    team_identifier: str = ""
    signing_identifier: str = ""
    signing_status: str = "unknown"


@dataclass(frozen=True)
class SecurityControlChangeEvent:
    event_id: str
    schema_version: int
    event_type: str
    control_id: str
    category: str
    detected_at_utc: datetime
    occurred_at_utc: datetime | None
    previous_state_digest: str | None
    current_state_digest: str
    previous_state_summary: Mapping[str, Any]
    current_state_summary: Mapping[str, Any]
    changed_fields: tuple[str, ...]
    authorization_status: str
    authorization_id: str | None
    actor: ActorIdentity | None
    process: ProcessIdentity | None
    evidence_sources: tuple[str, ...]
    confidence: float
    reference_cvss_score: float | None
    reference_cvss_vector: str | None
    msaa_incident_risk_score: float
    severity: str
    severity_reason: str
    attack_mappings: tuple[str, ...]
    incident_id: str | None
    first_seen_utc: datetime
    last_seen_utc: datetime
    occurrence_count: int
    acknowledgment_status: str
    integrity_digest: str
    missing_telemetry: tuple[str, ...] = ()
    scoring_version: str = "security-controls-risk-v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SensorHealth:
    mode: SensorMode
    checked_at_utc: datetime
    capabilities: Mapping[str, bool]
    last_heartbeat_utc: datetime | None = None
    details: Mapping[str, str] = field(default_factory=dict)
