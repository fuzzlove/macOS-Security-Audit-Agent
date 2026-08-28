from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .verifier import canonical_json


def default_license_root() -> Path:
    configured = os.environ.get("MSAA_LICENSE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "Library" / "Application Support" / "MSAA" / "Licensing"


class LicenseStorage:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_license_root()).expanduser()
        self.license_path = self.root / "license.json"
        self.install_id_path = self.root / "install_id"
        self.state_path = self.root / "verification_state.json"
        self.audit_path = self.root / "licensing_audit.jsonl"

    def _ensure_root(self) -> None:
        if self.root.exists() and self.root.is_symlink():
            raise OSError("Licensing directory may not be a symbolic link")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass

    def _atomic_write(self, path: Path, data: bytes, mode: int = 0o600) -> None:
        self._ensure_root()
        if path.exists() and path.is_symlink():
            raise OSError(f"Refusing symbolic-link licensing path: {path.name}")
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(self.root))
        temp_path = Path(temp_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def install_id(self) -> str:
        self._ensure_root()
        if self.install_id_path.exists():
            if self.install_id_path.is_symlink():
                raise OSError("Installation identifier may not be a symbolic link")
            value = self.install_id_path.read_text(encoding="ascii").strip()
            if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
                return value
            raise OSError("Installation identifier is corrupted")
        value = secrets.token_hex(32)
        self._atomic_write(self.install_id_path, (value + "\n").encode("ascii"))
        return value

    def device_fingerprint(self, product_id: str) -> str:
        return hashlib.sha256(f"{product_id}\0{self.install_id()}".encode()).hexdigest()

    def read_license(self, maximum_bytes: int) -> dict[str, Any] | None:
        if not self.license_path.exists():
            return None
        if self.license_path.is_symlink():
            raise OSError("License document may not be a symbolic link")
        if self.license_path.stat().st_size > maximum_bytes:
            raise OSError("License document exceeds the configured size limit")
        value = json.loads(self.license_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise TypeError("License document must be a JSON object")
        return value

    def store_verified_license(self, document: Mapping[str, Any]) -> None:
        self._atomic_write(self.license_path, canonical_json(document) + b"\n")

    def read_state(self) -> dict[str, Any]:
        if not self.state_path.exists() or self.state_path.is_symlink():
            return {}
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def write_state(self, state: Mapping[str, Any]) -> None:
        self._atomic_write(self.state_path, canonical_json(state) + b"\n")

    def audit(self, action: str, result: str, **details: Any) -> None:
        self._ensure_root()
        if self.audit_path.exists() and self.audit_path.is_symlink():
            raise OSError("Licensing audit log may not be a symbolic link")
        previous_hash = "0" * 64
        if self.audit_path.exists() and not self.audit_path.is_symlink():
            try:
                with self.audit_path.open("rb") as existing:
                    existing.seek(0, os.SEEK_END)
                    size = existing.tell()
                    existing.seek(max(0, size - 65_536))
                    last = existing.read().decode("utf-8").splitlines()[-1]
                previous_hash = str(json.loads(last).get("record_hash", previous_hash))
            except (OSError, UnicodeDecodeError, ValueError, IndexError):
                pass
        safe_details = {key: value for key, value in details.items() if key not in {"activation_code", "token", "password", "secret"}}
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "result": result,
            "details": safe_details,
            "previous_hash": previous_hash,
        }
        record["record_hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        descriptor = os.open(self.audit_path, flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.write(descriptor, canonical_json(record) + b"\n")
            os.fsync(descriptor)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def verify_audit_chain(self, maximum_bytes: int = 10_485_760) -> dict[str, Any]:
        if not self.audit_path.exists():
            return {"status": "EMPTY", "records": 0}
        if self.audit_path.is_symlink() or self.audit_path.stat().st_size > maximum_bytes:
            return {"status": "INVALID", "records": 0, "reason": "unsafe_or_oversized_audit_log"}
        previous_hash = "0" * 64
        records = 0
        try:
            with self.audit_path.open("rb") as handle:
                for raw_line in handle:
                    record = json.loads(raw_line)
                    if not isinstance(record, dict) or record.get("previous_hash") != previous_hash:
                        return {"status": "INVALID", "records": records, "reason": "chain_link_mismatch"}
                    claimed_hash = str(record.pop("record_hash", ""))
                    calculated_hash = hashlib.sha256(canonical_json(record)).hexdigest()
                    if not secrets.compare_digest(claimed_hash, calculated_hash):
                        return {"status": "INVALID", "records": records, "reason": "record_hash_mismatch"}
                    previous_hash = claimed_hash
                    records += 1
        except (OSError, UnicodeDecodeError, ValueError):
            return {"status": "INVALID", "records": records, "reason": "audit_parse_failure"}
        return {"status": "VALID", "records": records, "head_hash": previous_hash}
