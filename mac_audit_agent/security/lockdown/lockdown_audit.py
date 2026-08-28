from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def write_evidence(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = dict(payload)
    body.pop("integrity", None)
    body.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    body["integrity"] = {"algorithm": "sha256", "payload_sha256": hashlib.sha256(canonical_json(body)).hexdigest()}
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(json.dumps(body, indent=2, sort_keys=True, default=str).encode())
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    return path


def verify_evidence(payload: dict[str, Any]) -> bool:
    body = dict(payload)
    integrity = body.pop("integrity", None)
    return bool(
        isinstance(integrity, dict)
        and integrity.get("algorithm") == "sha256"
        and integrity.get("payload_sha256") == hashlib.sha256(canonical_json(body)).hexdigest()
    )


class AuditChain:
    def __init__(self, path: Path) -> None: self.path = path

    def append(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        previous = "0" * 64
        if self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines: previous = str(json.loads(lines[-1]).get("record_hash", previous))
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "payload": payload, "previous_hash": previous}
        record["record_hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle: handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.chmod(self.path, 0o600)
        return record
