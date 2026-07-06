from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso


DEFAULT_EVIDENCE_PATH = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "quality" / "verification_evidence.json"


@dataclass
class VerificationEvidence:
    evidence_id: str
    check_id: str
    command: str
    started_at: str
    completed_at: str
    status: str
    exit_code: int
    evidence_summary: str
    artifacts: list[str] = field(default_factory=list)
    expires_at: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evidence_path(path: Path | None = None) -> Path:
    if path is not None:
        return path.expanduser()
    override = os.environ.get("MSAA_VERIFICATION_EVIDENCE_PATH", "")
    return Path(override).expanduser() if override else DEFAULT_EVIDENCE_PATH


def load_evidence(path: Path | None = None) -> list[dict[str, Any]]:
    target = evidence_path(path)
    if not target.exists():
        return []
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, dict):
        records = payload.get("records", [])
    else:
        records = payload
    return [item for item in records if isinstance(item, dict)]


def save_evidence(record: VerificationEvidence | dict[str, Any], path: Path | None = None) -> Path:
    target = evidence_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    records = load_evidence(target)
    payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    records = [item for item in records if item.get("evidence_id") != payload.get("evidence_id")]
    records.append(payload)
    target.write_text(json.dumps({"records": records[-200:]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def record_verification_evidence(
    *,
    check_id: str,
    command: str,
    started_at: str,
    completed_at: str,
    status: str,
    exit_code: int,
    evidence_summary: str,
    artifacts: list[str] | None = None,
    ttl_hours: int | None = None,
    details: dict[str, Any] | None = None,
    path: Path | None = None,
) -> VerificationEvidence:
    expires_at = ""
    if ttl_hours:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    record = VerificationEvidence(
        evidence_id=f"evidence-{uuid4().hex[:12]}",
        check_id=check_id,
        command=command,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        exit_code=exit_code,
        evidence_summary=evidence_summary,
        artifacts=artifacts or [],
        expires_at=expires_at,
        details=details or {},
    )
    save_evidence(record, path)
    return record


def latest_evidence(check_id: str, path: Path | None = None) -> dict[str, Any] | None:
    records = [item for item in load_evidence(path) if item.get("check_id") == check_id]
    if not records:
        return None
    return sorted(records, key=lambda item: str(item.get("completed_at", "")))[-1]


def evidence_is_fresh(record: dict[str, Any] | None, *, max_age_hours: int = 24) -> bool:
    if not record or str(record.get("status", "")).lower() not in {"pass", "passed", "verified"}:
        return False
    completed_at = str(record.get("completed_at", ""))
    try:
        completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if completed.tzinfo is None:
        completed = completed.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - completed > timedelta(hours=max_age_hours):
        return False
    expires_at = str(record.get("expires_at", ""))
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            return False
    return True


def new_started_at() -> str:
    return utc_now_iso()


__all__ = [
    "VerificationEvidence",
    "evidence_is_fresh",
    "evidence_path",
    "latest_evidence",
    "load_evidence",
    "new_started_at",
    "record_verification_evidence",
    "save_evidence",
]
