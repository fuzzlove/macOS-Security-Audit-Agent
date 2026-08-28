"""Local authorization gate for non-observe protection modes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


AUTHORIZED_USE_STATEMENT = (
    "Use MSAA only on a local device you are authorized to protect. Monitoring is local-first, "
    "does not capture credentials or file contents by default, and provides no guarantee of prevention, "
    "certification, compliance, or government endorsement."
)


@dataclass(frozen=True)
class SafetyAcceptance:
    mode: str
    accepted: bool
    accepted_at: str
    statement_version: str = "1.0"

    def to_dict(self) -> dict:
        return asdict(self)


def requires_confirmation(mode: str) -> bool:
    return mode.lower().replace("_", " ") not in {"observe", "observation"}


def record_acceptance(path: Path, mode: str, *, confirmed: bool) -> SafetyAcceptance:
    if requires_confirmation(mode) and not confirmed:
        raise PermissionError("Explicit local authorization is required above Observe mode.")
    record = SafetyAcceptance(mode, confirmed or not requires_confirmation(mode), datetime.now(timezone.utc).isoformat())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict(), sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return record


__all__ = ["AUTHORIZED_USE_STATEMENT", "SafetyAcceptance", "record_acceptance", "requires_confirmation"]
