from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class TrustStore:
    def __init__(self, path: Path): self.path = path
    def load(self) -> list[dict[str, object]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8")); return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError): return []
    def trust(self, *, file_hash: str, bundle_id: str, team_id: str, canonical_path: str, reason: str, expires_at: str = "") -> None:
        records = [record for record in self.load() if record.get("file_hash") != file_hash]
        records.append({"file_hash": file_hash, "bundle_id": bundle_id, "team_id": team_id, "canonical_path": canonical_path, "reason": reason, "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": expires_at})
        self.path.parent.mkdir(parents=True, exist_ok=True); self.path.write_text(json.dumps(records, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    @staticmethod
    def valid(record: dict[str, object], *, file_hash: str, bundle_id: str, team_id: str, canonical_path: str) -> bool:
        return all(str(record.get(key, "")) == value for key, value in (("file_hash", file_hash), ("bundle_id", bundle_id), ("team_id", team_id), ("canonical_path", canonical_path)))
