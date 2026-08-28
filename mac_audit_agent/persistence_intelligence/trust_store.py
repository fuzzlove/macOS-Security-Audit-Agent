from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.persistence_intelligence.models import PersistenceItem


class PersistenceTrustStore:
    """User dispositions bound to artifact identity, never to a filename alone."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (Path.home() / "Library/Application Support/MacAuditAgent/persistence_trust.json")

    def _load(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {"schema_version": 1, "records": []}
        except (OSError, json.JSONDecodeError):
            return {"schema_version": 1, "records": []}

    def trust(self, item: PersistenceItem, *, user: str, reason: str) -> None:
        if not item.target_hash_sha256:
            raise ValueError("Trust requires a SHA-256 artifact identity; filename-only trust is prohibited.")
        record = {
            "sha256": item.target_hash_sha256,
            "canonical_path": str(Path(item.executable_path or item.path).expanduser().resolve(strict=False)),
            "bundle_id": item.bundle_id,
            "team_id": item.team_id,
            "user": user,
            "reason": reason.strip(),
            "created_at": utc_now_iso(),
        }
        payload = self._load()
        records = [entry for entry in payload.get("records", []) if entry.get("sha256") != record["sha256"]]
        records.append(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": 1, "records": records}, indent=2, sort_keys=True), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def apply(self, item: PersistenceItem) -> bool:
        canonical = str(Path(item.executable_path or item.path).expanduser().resolve(strict=False))
        for record in self._load().get("records", []):
            if not item.target_hash_sha256 or record.get("sha256") != item.target_hash_sha256:
                continue
            if record.get("canonical_path") != canonical or record.get("bundle_id", "") != item.bundle_id or record.get("team_id", "") != item.team_id:
                continue
            item.analyst_status = "trusted"
            item.trust_label = "User Trusted"
            item.evidence.append(f"User disposition: trusted by {record.get('user', 'unknown')} at {record.get('created_at', 'unknown')}; cryptographic classification is unchanged.")
            return True
        return False
