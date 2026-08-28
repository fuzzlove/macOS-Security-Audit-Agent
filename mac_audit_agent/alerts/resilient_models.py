from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class EventValidationError(ValueError):
    pass


class Priority(IntEnum):
    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4


SEVERITY_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PROTECTED_TYPES = {
    "agent_tampering", "logging_failure", "audit_log_integrity_failure", "event_store_corruption",
    "queue_overflow", "reserved_storage_exhaustion", "policy_modification", "suppression_rule_modification",
    "unauthorized_disable_attempt", "emergency_protection_disable_attempt", "security_control_failure",
    "privileged_helper_failure", "signature_verification_failure", "event_source_authentication_failure",
    "configuration_integrity_failure", "system_time_rollback", "critical_severity_escalation",
    "alert_flood_detected", "log_storage_pressure", "cardinality_pressure",
}

_SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|api[_-]?key|bearer|cookie|session|authorization|private[_-]?key|access[_-]?token|refresh[_-]?token)")
_SECRET_TEXT = re.compile(r"(?i)\b(bearer\s+|api[_-]?key\s*[=:]\s*|password\s*[=:]\s*)([^\s,;]+)")


def redact(value: Any, *, depth: int = 0, max_depth: int = 8, max_items: int = 128, max_string: int = 16_384) -> Any:
    if depth > max_depth:
        raise EventValidationError("maximum nesting depth exceeded")
    if isinstance(value, dict):
        if len(value) > max_items:
            raise EventValidationError("maximum map size exceeded")
        output: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            name = str(key)[:256]
            output[name] = "[REDACTED]" if _SENSITIVE_KEY.search(name) else redact(item, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string)
        return output
    if isinstance(value, (list, tuple)):
        if len(value) > max_items:
            raise EventValidationError("maximum array size exceeded")
        return [redact(item, depth=depth + 1, max_depth=max_depth, max_items=max_items, max_string=max_string) for item in value[:max_items]]
    if isinstance(value, bytes):
        raise EventValidationError("binary event fields are not accepted")
    if isinstance(value, str):
        return _SECRET_TEXT.sub(lambda match: match.group(1) + "[REDACTED]", value[:max_string])
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:max_string]


@dataclass
class SecurityEvent:
    event_id: str
    event_type: str
    rule_id: str
    severity: str
    confidence: str
    timestamp_utc: str
    monotonic_timestamp: float
    ingestion_timestamp_utc: str
    source_id: str
    source_type: str = "local_detector"
    schema_version: int = 1
    rule_version: str = "1"
    sequence_number: int = 0
    source_process: str = ""
    source_pid: int | None = None
    host_id: str = ""
    hostname: str = ""
    user_uid: int | None = None
    user_name: str = ""
    process_path: str = ""
    process_signing_identifier: str = ""
    process_team_identifier: str = ""
    process_hash: str = ""
    parent_process: str = ""
    remote_address: str = ""
    remote_port: int | None = None
    object_path: str = ""
    action: str = ""
    outcome: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    mitre_attack: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    threat_tags: list[str] = field(default_factory=list)
    correlation_id: str = ""
    incident_id: str = ""
    fingerprint: str = ""
    material_digest: str = ""
    notification_disposition: str = "pending"
    suppression_rule_id: str = ""
    suppression_reason: str = ""
    previous_integrity_hash: str = ""
    event_integrity_hash: str = ""

    def validate(self, maximum_event_size: int = 262_144, *, maximum_string_length: int = 16_384, maximum_nesting_depth: int = 8, maximum_collection_items: int = 128) -> None:
        if self.schema_version != 1:
            raise EventValidationError(f"unsupported schema version: {self.schema_version}")
        for name in ("event_id", "event_type", "rule_id", "severity", "timestamp_utc", "source_id"):
            if not str(getattr(self, name, "")).strip():
                raise EventValidationError(f"missing required field: {name}")
        if self.severity.lower() not in SEVERITY_RANK:
            raise EventValidationError("invalid severity")
        bounded = {
            "event_id": 256, "event_type": 256, "rule_id": 256, "rule_version": 64,
            "severity": 32, "confidence": 64, "timestamp_utc": 64,
            "ingestion_timestamp_utc": 64, "source_id": 256, "source_type": 128,
            "source_process": 1024, "host_id": 256, "hostname": 256,
            "user_name": 256, "process_path": 4096, "process_signing_identifier": 512,
            "process_team_identifier": 128, "process_hash": 256, "parent_process": 4096,
            "remote_address": 512, "object_path": 4096, "action": 512, "outcome": 256,
            "correlation_id": 256, "incident_id": 256,
        }
        for name, limit in bounded.items():
            value = str(getattr(self, name, ""))
            if len(value) > limit:
                raise EventValidationError(f"field exceeds maximum length: {name}")
        if self.source_pid is not None and (not isinstance(self.source_pid, int) or self.source_pid < 0):
            raise EventValidationError("source_pid must be a non-negative integer")
        if self.remote_port is not None and (not isinstance(self.remote_port, int) or not 0 <= self.remote_port <= 65535):
            raise EventValidationError("remote_port is invalid")
        if self.user_uid is not None and (not isinstance(self.user_uid, int) or self.user_uid < 0):
            raise EventValidationError("user_uid must be a non-negative integer")
        for name in ("mitre_attack", "cve_ids", "threat_tags"):
            values = getattr(self, name)
            if not isinstance(values, list) or len(values) > 64 or any(not isinstance(item, str) or len(item) > 256 for item in values):
                raise EventValidationError(f"{name} must contain at most 64 bounded strings")
        self.attributes = redact(self.attributes,max_depth=maximum_nesting_depth,max_items=maximum_collection_items,max_string=maximum_string_length)
        encoded = self.canonical_json().encode("utf-8")
        if len(encoded) > maximum_event_size:
            raise EventValidationError(f"event exceeds {maximum_event_size} bytes")

    @property
    def protected(self) -> bool:
        normalized = self.event_type.lower().replace("-", "_")
        return normalized in PROTECTED_TYPES or self.severity.lower() == "critical" and "escalat" in normalized

    @property
    def priority(self) -> Priority:
        if self.protected:
            return Priority.P0
        return {"critical": Priority.P1, "high": Priority.P2, "medium": Priority.P3}.get(self.severity.lower(), Priority.P4)

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
