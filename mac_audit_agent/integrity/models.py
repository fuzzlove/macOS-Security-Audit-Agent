from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from mac_audit_agent.integrity.manifest import IntegrityFileEntry, IntegrityManifest
from mac_audit_agent.integrity.verifier import IntegrityVerificationResult


IntegrityStatus = Literal[
    "verified",
    "verified_with_warnings",
    "modified",
    "stale",
    "incompatible_manifest",
    "partial",
    "unknown",
    "draft",
    "failed",
]

HealthImpact = Literal["healthy", "degraded", "broken", "critical"]


@dataclass(frozen=True)
class IntegrityFileResult:
    relative_path: str
    status: str
    expected_sha256: str = ""
    actual_sha256: str = ""
    expected_size: int = 0
    actual_size: int = 0
    expected_mode: str = ""
    actual_mode: str = ""
    expected_owner: str = ""
    actual_owner: str = ""
    message: str = ""

    @classmethod
    def from_verifier_payload(cls, payload: dict[str, Any]) -> "IntegrityFileResult":
        return cls(
            relative_path=str(payload.get("relative_path", "")),
            status=str(payload.get("verification_status", payload.get("status", "unknown"))),
            expected_sha256=str(payload.get("sha256", "")),
            actual_sha256=str(payload.get("observed_sha256", "")),
            expected_size=int(payload.get("size_bytes") or 0),
            actual_size=int(payload.get("observed_size") or 0),
            expected_mode=str(payload.get("mode", "")),
            actual_mode=str(payload.get("observed_mode", "")),
            expected_owner=str(payload.get("owner", "")),
            actual_owner=str(payload.get("observed_owner", "")),
            message=str(payload.get("error", "") or ", ".join(str(item) for item in payload.get("mismatch_reasons", []))),
        )


__all__ = [
    "HealthImpact",
    "IntegrityFileEntry",
    "IntegrityFileResult",
    "IntegrityManifest",
    "IntegrityStatus",
    "IntegrityVerificationResult",
]
