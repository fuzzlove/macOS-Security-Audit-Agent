"""Typed models shared by definition sources, validation, storage, and UI."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


class StringEnum(str, Enum):
    pass


class DefinitionType(StringEnum):
    YARA_RULE = "YARA_RULE"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    URL = "URL"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    CIDR = "CIDR"
    CERTIFICATE_HASH = "CERTIFICATE_HASH"
    CERTIFICATE_IDENTITY = "CERTIFICATE_IDENTITY"
    MALWARE_FAMILY = "MALWARE_FAMILY"
    IOC = "IOC"
    BEHAVIOR_RULE = "BEHAVIOR_RULE"
    DETECTION_RULE = "DETECTION_RULE"
    ALLOWLIST = "ALLOWLIST"
    DENYLIST = "DENYLIST"


class DefinitionAction(StringEnum):
    OBSERVE = "OBSERVE"
    LOG = "LOG"
    ALERT = "ALERT"
    CORRELATE = "CORRELATE"
    QUARANTINE_CANDIDATE = "QUARANTINE_CANDIDATE"
    BLOCK = "BLOCK"
    DISABLED = "DISABLED"


class DefinitionLifecycle(StringEnum):
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISABLED = "DISABLED"
    SUPERSEDED = "SUPERSEDED"


class DefinitionFreshness(StringEnum):
    CURRENT = "CURRENT"
    AGING = "AGING"
    STALE = "STALE"
    VERY_STALE = "VERY_STALE"
    UNKNOWN = "UNKNOWN"


class TrustClass(StringEnum):
    AUTHORITATIVE = "AUTHORITATIVE"
    TRUSTED = "TRUSTED"
    COMMUNITY = "COMMUNITY"
    LOCAL_ADMIN = "LOCAL_ADMIN"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNTRUSTED = "UNTRUSTED"


class DefinitionTrustLevel(IntEnum):
    """Portable source trust labels; the number is never promoted by merging."""

    TRUST_1_UNVERIFIED = 1
    TRUST_2_RESEARCH = 2
    TRUST_3_ESTABLISHED_COMMUNITY = 3
    TRUST_4_VENDOR_VERIFIED = 4
    TRUST_5_MSAA_VERIFIED = 5


class DefinitionHealthState(StringEnum):
    HEALTHY = "HEALTHY"
    UPDATING = "UPDATING"
    STALE = "STALE"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    ROLLBACK_ACTIVE = "ROLLBACK_ACTIVE"
    NEVER_UPDATED = "NEVER_UPDATED"


class Severity(StringEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ValidationState(StringEnum):
    UNKNOWN = "UNKNOWN"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class DefinitionProvenance:
    source_id: str
    source_reference: str | None = None
    retrieved_at: datetime = field(default_factory=utc_now)
    original_value: str | None = None
    source_confidence: float = 0.5
    trust_class: TrustClass = TrustClass.COMMUNITY
    dependency_group: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["retrieved_at"] = _timestamp(self.retrieved_at)
        payload["trust_class"] = self.trust_class.value
        return payload


@dataclass(frozen=True)
class ThreatDefinition:
    definition_id: str
    definition_type: DefinitionType
    value: str
    confidence: float = 0.5
    severity: Severity = Severity.MEDIUM
    malware_family: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    imported_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    tags: tuple[str, ...] = ()
    action: DefinitionAction = DefinitionAction.CORRELATE
    lifecycle: DefinitionLifecycle = DefinitionLifecycle.NEW
    provenance: tuple[DefinitionProvenance, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def canonical_key(self) -> str:
        return f"{self.definition_type.value}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition_id": self.definition_id,
            "definition_type": self.definition_type.value,
            "value": self.value,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "malware_family": self.malware_family,
            "first_seen": _timestamp(self.first_seen),
            "last_seen": _timestamp(self.last_seen),
            "created_at": _timestamp(self.created_at),
            "imported_at": _timestamp(self.imported_at),
            "expires_at": _timestamp(self.expires_at),
            "tags": list(self.tags),
            "action": self.action.value,
            "lifecycle": self.lifecycle.value,
            "provenance": [item.to_dict() for item in self.provenance],
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class SourcePolicy:
    source_id: str
    display_name: str
    trust_class: TrustClass
    source_confidence: float
    enabled: bool = False
    trust_level: DefinitionTrustLevel = DefinitionTrustLevel.TRUST_3_ESTABLISHED_COMMUNITY
    dependency_group: str | None = None
    license_name: str = "review-required"
    terms_reference: str = ""
    redistribution_allowed: bool | None = None
    commercial_use_status: str = "REVIEW_REQUIRED"
    attribution_required: str = ""
    minimum_interval_seconds: int = 3600
    expected_minimum_count: int = 1
    maximum_reduction_fraction: float = 0.75
    maximum_growth_factor: float = 20.0
    default_action: DefinitionAction = DefinitionAction.CORRELATE
    required: bool = False
    update_interval_seconds: int | None = None
    timeout_seconds: int = 30
    maximum_download_bytes: int = 32 * 1024 * 1024

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["trust_class"] = self.trust_class.value
        payload["trust_level"] = int(self.trust_level)
        payload["default_action"] = self.default_action.value
        return payload


@dataclass(frozen=True)
class UpdateMetadata:
    source_id: str
    available: bool
    version: str | None = None
    modified_at: datetime | None = None
    etag: str | None = None
    entry_count: int | None = None
    message: str = ""


@dataclass(frozen=True)
class RawDefinitionPackage:
    source_id: str
    payload: bytes
    retrieved_at: datetime = field(default_factory=utc_now)
    content_type: str = "application/octet-stream"
    source_reference: str | None = None
    expected_sha256: str | None = None
    signature: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    severity: Severity = Severity.HIGH
    definition_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "severity": self.severity.value, "definition_id": self.definition_id}


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    state: ValidationState
    issues: tuple[ValidationIssue, ...] = ()
    accepted_count: int = 0
    rejected_count: int = 0
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "state": self.state.value,
            "issues": [item.to_dict() for item in self.issues],
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "metrics": self.metrics,
        }


@dataclass(frozen=True)
class SourceStatus:
    source_id: str
    state: str
    enabled: bool
    last_attempt: datetime | None = None
    last_success: datetime | None = None
    version: str | None = None
    definition_count: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id, "state": self.state, "enabled": self.enabled,
            "last_attempt": _timestamp(self.last_attempt), "last_success": _timestamp(self.last_success),
            "version": self.version, "definition_count": self.definition_count, "error": self.error,
        }


@dataclass(frozen=True)
class DefinitionHealth:
    state: str
    freshness: DefinitionFreshness
    active_version: str | None
    activated_at: datetime | None
    definition_count: int
    counts_by_type: dict[str, int]
    validation_state: ValidationState
    last_update_attempt: datetime | None = None
    last_successful_update: datetime | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state, "freshness": self.freshness.value, "active_version": self.active_version,
            "activated_at": _timestamp(self.activated_at), "definition_count": self.definition_count,
            "counts_by_type": self.counts_by_type, "validation_state": self.validation_state.value,
            "last_update_attempt": _timestamp(self.last_update_attempt),
            "last_successful_update": _timestamp(self.last_successful_update), "message": self.message,
        }


@dataclass(frozen=True)
class BehaviorRuleDefinition:
    rule_id: str
    version: str
    description: str
    severity: Severity
    confidence: float
    required_telemetry: tuple[str, ...]
    conditions: dict[str, Any]
    exclusions: tuple[dict[str, Any], ...] = ()
    mitre_attack: tuple[str, ...] = ()
    recommended_response: str = "Review correlated evidence."
    platform_classification: str = "MACOS_NATIVE"

    def canonical_value(self) -> str:
        return json.dumps({
            "rule_id": self.rule_id, "version": self.version, "description": self.description,
            "severity": self.severity.value, "confidence": self.confidence,
            "required_telemetry": list(self.required_telemetry), "conditions": self.conditions,
            "exclusions": list(self.exclusions), "mitre_attack": list(self.mitre_attack),
            "recommended_response": self.recommended_response,
            "platform_classification": self.platform_classification,
        }, sort_keys=True, separators=(",", ":"))


__all__ = [name for name in globals() if name[0].isupper()] + ["utc_now"]
