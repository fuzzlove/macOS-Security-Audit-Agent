from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Tuple


class GuardProfile(str, Enum):
    DISABLED = "DISABLED"
    AUDIT = "AUDIT"
    WARN = "WARN"
    PROTECT = "PROTECT"
    HIGH_ASSURANCE = "HIGH_ASSURANCE"


class Classification(str, Enum):
    NOT_TEXT = "NOT_TEXT"
    PLAIN_TEXT = "PLAIN_TEXT"
    SOURCE_CODE_FRAGMENT = "SOURCE_CODE_FRAGMENT"
    COMMAND_LIKE = "COMMAND_LIKE"
    SCRIPT_LIKE = "SCRIPT_LIKE"
    ENCODED_COMMAND = "ENCODED_COMMAND"
    DOWNLOAD_AND_EXECUTE = "DOWNLOAD_AND_EXECUTE"
    SECURITY_IMPAIRMENT = "SECURITY_IMPAIRMENT"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    PERSISTENCE_COMMAND = "PERSISTENCE_COMMAND"
    POTENTIAL_CLICKFIX = "POTENTIAL_CLICKFIX"
    CLASSIFICATION_FAILED = "CLASSIFICATION_FAILED"


@dataclass(frozen=True)
class ClipboardEvidence:
    access_state: str
    classification: str
    sha256: Optional[str]
    change_count: Optional[int]
    content_type: str
    character_count: Optional[int]
    byte_count: Optional[int]
    line_count: Optional[int]
    language_candidates: Tuple[str, ...]
    matched_categories: Tuple[str, ...]
    entropy_estimate: Optional[float]
    encoding_indicators: Tuple[str, ...]
    redacted_preview: Optional[str]
    inspected_at_utc: datetime
    classifier_version: Optional[str]
    classifier_signature_valid: bool
    confidence: float
    truncated: bool


@dataclass(frozen=True)
class ClickFixShortcutEvent:
    event_id: str
    schema_version: int
    detected_at_utc: datetime
    monotonic_timestamp_ns: int
    key_code: int
    modifier_flags: int
    physical_event: bool
    replay_event: bool
    foreground_pid: Optional[int]
    foreground_bundle_id: Optional[str]
    foreground_signing_identifier: Optional[str]
    clipboard_change_count: Optional[int]
    clipboard_access_state: str
    clipboard_classification: str
    clipboard_sha256: Optional[str]
    clipboard_byte_length: Optional[int]
    classifier_version: Optional[str]
    msaa_incident_risk_score: float
    severity: str
    sensor_mode: str
    input_monitoring_state: str
    accessibility_state: str
    persisted_at_utc: datetime
    integrity_digest: str
    foreground_team_identifier: Optional[str] = None
    audit_session_id: Optional[int] = None
    console_user: Optional[str] = None
    display_session: Optional[str] = None
    clipboard_source_attribution: str = "UNKNOWN"
    clipboard_source_inference: str = "FOREGROUND_APP_AT_CHANGE"
    clipboard_source_confidence: str = "LOW"
    spotlight_suppressed: bool = False
    shortcut_replayed: bool = False
    missing_telemetry: Tuple[str, ...] = ()
    attack_mappings: Tuple[str, ...] = ("T1204.004",)
    scoring_version: str = "clickfix-risk-v1"
    authorization_status: str = "AUTHORIZATION_UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("detected_at_utc", "persisted_at_utc"):
            result[key] = result[key].isoformat()
        return result


@dataclass(frozen=True)
class ClickFixIncident:
    incident_id: str
    shortcut_event_id: str
    disposition: str
    created_at_utc: datetime
    first_seen_utc: datetime
    last_seen_utc: datetime
    severity: str
    risk_score: float
    confidence: float
    command_categories: Tuple[str, ...]
    attack_mappings: Tuple[str, ...]
    clipboard_quarantined: bool
    spotlight_suppressed: bool
    terminal_launch_observed: bool
    follow_on_execution_observed: bool
    containment_status: str
    acknowledgment_status: str
    integrity_digest: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("created_at_utc", "first_seen_utc", "last_seen_utc"):
            result[key] = result[key].isoformat()
        return result


ERROR_CODES = tuple("CFX%03d_%s" % item for item in (
    (1, "SENSOR_NOT_INSTALLED"), (2, "SENSOR_NOT_RUNNING"),
    (3, "INPUT_MONITORING_DENIED"), (4, "ACCESSIBILITY_DENIED"),
    (5, "CLIPBOARD_ACCESS_DENIED"), (6, "CLIPBOARD_READ_TIMEOUT"),
    (7, "CLIPBOARD_TOO_LARGE"), (8, "CLASSIFICATION_FAILED"),
    (9, "CLASSIFIER_SIGNATURE_INVALID"), (10, "EVENT_TAP_DISABLED"),
    (11, "EVENT_TAP_TIMEOUT"), (12, "XPC_AUTHENTICATION_FAILED"),
    (13, "EVENT_QUEUE_OVERFLOW"), (14, "EVIDENCE_PERSISTENCE_FAILED"),
    (15, "SHORTCUT_REPLAY_FAILED"), (16, "CLIPBOARD_QUARANTINE_FAILED"),
    (17, "NOTIFICATION_DELIVERY_FAILED"), (18, "CORRELATION_SENSOR_UNAVAILABLE"),
    (19, "ENDPOINT_SECURITY_UNAVAILABLE"), (20, "PROTECT_MODE_DEGRADED"),
))
