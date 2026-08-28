from __future__ import annotations

from dataclasses import asdict, dataclass, field
from mac_audit_agent.compat.enum import StrEnum
from typing import Any


class IntegrityTrustStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    WARNING = "warning"


class ReleaseGateStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    WARNING = "warning"


@dataclass(slots=True)
class ReleaseGateMappedFailure:
    domain: str
    failure_code: str
    message: str
    integrity_status: str = ""
    release_gate_status: str = "blocked"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def map_release_gate_exception(exc: Exception, *, integrity_status: str = "") -> ReleaseGateMappedFailure:
    text = str(exc)
    if "require-clean-git" in text or "dirty source tree" in text:
        return ReleaseGateMappedFailure(
            domain="release_gate",
            failure_code="RELEASE_GATE_DIRTY_SOURCE_TREE",
            message="Public release is blocked because the source tree has uncommitted changes.",
            integrity_status=integrity_status,
            details={"exception": type(exc).__name__, "raw_message": text},
        )
    return ReleaseGateMappedFailure(
        domain="release_gate",
        failure_code="RELEASE_GATE_BLOCKED",
        message="Public release gate is blocked by a non-integrity release prerequisite.",
        integrity_status=integrity_status,
        details={"exception": type(exc).__name__, "raw_message": text},
    )


def release_gate_failure_for_code(code: str, *, integrity_status: str = "") -> ReleaseGateMappedFailure:
    mapping = {
        "RELEASE_GATE_DIRTY_SOURCE_TREE": "Public release is blocked because the source tree has uncommitted changes.",
        "RELEASE_GATE_TESTS_FAILED": "Public release is blocked because tests failed.",
        "RELEASE_GATE_CLEAN_INSTALL_MISSING": "Public release is blocked because clean install verification is missing.",
    }
    return ReleaseGateMappedFailure(
        domain="release_gate",
        failure_code=code,
        message=mapping.get(code, "Public release gate is blocked."),
        integrity_status=integrity_status,
    )


def map_integrity_failure(code: str, *, message: str = "") -> ReleaseGateMappedFailure:
    """Map only genuine authority failures into the integrity domain."""
    normalized = {
        "SIGNATURE_INVALID": "The canonical manifest signature is invalid.",
        "MANIFEST_MISSING": "The canonical integrity manifest is missing.",
    }
    if code not in normalized:
        raise ValueError(f"Unsupported integrity-domain failure code: {code}")
    return ReleaseGateMappedFailure(
        domain="integrity",
        failure_code=code,
        message=message or normalized[code],
        integrity_status=IntegrityTrustStatus.FAILED.value,
        release_gate_status="",
    )


__all__ = [
    "IntegrityTrustStatus",
    "ReleaseGateMappedFailure",
    "ReleaseGateStatus",
    "map_integrity_failure",
    "map_release_gate_exception",
    "release_gate_failure_for_code",
]
