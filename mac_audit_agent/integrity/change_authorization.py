from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.strict_verifier import IntegrityDiffReport


@dataclass(frozen=True)
class AuthorizedChangeRecord:
    authorization_id: str
    timestamp: str
    user_confirmation: str
    reason: str
    file_paths: list[str]
    hash_snapshot: dict[str, str]
    diff_snapshot_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthorizedChangeRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (Path.home() / ".mac_audit_agent" / "integrity" / "authorized_changes.json")

    def list_authorized_changes(self) -> list[AuthorizedChangeRecord]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return []
        records = payload.get("authorized_changes", [])
        return [AuthorizedChangeRecord(**item) for item in records if isinstance(item, dict)]

    def authorize(self, report: IntegrityDiffReport, *, user_confirmation: str, reason: str) -> AuthorizedChangeRecord:
        if user_confirmation.strip() != "I ACKNOWLEDGE THESE CHANGES":
            raise ValueError("explicit integrity change acknowledgement is required")
        changes = report.all_changes
        snapshot = {change.file_path: change.actual_hash for change in changes}
        serialized = json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":"))
        record = AuthorizedChangeRecord(
            authorization_id=f"integrity-auth-{uuid.uuid4().hex}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_confirmation=user_confirmation,
            reason=reason,
            file_paths=[change.file_path for change in changes],
            hash_snapshot=snapshot,
            diff_snapshot_hash=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        )
        records = [item.to_dict() for item in self.list_authorized_changes()]
        records.append(record.to_dict())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"authorized_changes": records}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return record

    def has_authorization_for_report(self, report: IntegrityDiffReport) -> bool:
        current = {change.file_path: change.actual_hash for change in report.all_changes}
        for record in self.list_authorized_changes():
            if record.hash_snapshot == current:
                return True
        return False
