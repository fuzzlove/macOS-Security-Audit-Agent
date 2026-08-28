from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class LicenseState(str, Enum):
    VALID = "VALID"
    EXPIRING = "EXPIRING"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    UNLICENSED = "UNLICENSED"
    INVALID = "INVALID"
    DEVICE_MISMATCH = "DEVICE_MISMATCH"
    CLOCK_ROLLBACK_SUSPECTED = "CLOCK_ROLLBACK_SUSPECTED"
    VERIFIER_UNAVAILABLE = "VERIFIER_UNAVAILABLE"


class LicenseFeature(str, Enum):
    CORE_PROTECTION = "core_protection"
    ALERTING = "alerting"
    EVIDENCE_PRESERVATION = "evidence_preservation"
    INCIDENT_RESPONSE = "incident_response"
    INTEGRITY_VERIFICATION = "integrity_verification"
    PROFESSIONAL_REPORTS = "professional_reports"
    ENTERPRISE_INTEGRATIONS = "enterprise_integrations"
    MANAGED_POLICY = "managed_policy"
    COMMERCIAL_USE = "commercial_use"


CORE_SAFETY_FEATURES = frozenset(
    {
        LicenseFeature.CORE_PROTECTION.value,
        LicenseFeature.ALERTING.value,
        LicenseFeature.EVIDENCE_PRESERVATION.value,
        LicenseFeature.INCIDENT_RESPONSE.value,
        LicenseFeature.INTEGRITY_VERIFICATION.value,
    }
)


@dataclass(frozen=True)
class LicenseStatus:
    state: LicenseState
    message: str
    license_id: str = ""
    edition: str = "UNLICENSED"
    licensed_to: str = ""
    issued_at: str = ""
    expires_at: str | None = None
    maintenance_until: str | None = None
    features: tuple[str, ...] = ()
    activation_mode: str = "none"
    device_bound: bool = False
    key_id: str = ""
    last_verified_at: str = ""
    days_remaining: int | None = None
    warnings: tuple[str, ...] = ()
    error_code: str = ""
    core_protection_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.state in {LicenseState.VALID, LicenseState.EXPIRING}

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        result["valid"] = self.valid
        return result
