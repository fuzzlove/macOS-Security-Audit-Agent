from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from mac_audit_agent.compat.datetime_compat import UTC, utc_now
from typing import Any


@dataclass(slots=True)
class EvidenceFreshnessResult:
    status: str
    last_verified_at: str
    current_command_started_at: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def verify_evidence_freshness(*, last_verified_at: str, command_started_at: str) -> EvidenceFreshnessResult:
    if not last_verified_at:
        return EvidenceFreshnessResult("failed", last_verified_at, command_started_at, "verification did not produce current evidence")
    try:
        verified = _parse(last_verified_at)
        started = _parse(command_started_at)
    except ValueError as exc:
        return EvidenceFreshnessResult("failed", last_verified_at, command_started_at, f"invalid timestamp: {exc}")
    if verified < started:
        return EvidenceFreshnessResult("failed", last_verified_at, command_started_at, "verification evidence predates current command")
    return EvidenceFreshnessResult("passed", last_verified_at, command_started_at)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


__all__ = ["EvidenceFreshnessResult", "utc_now_iso", "verify_evidence_freshness"]
