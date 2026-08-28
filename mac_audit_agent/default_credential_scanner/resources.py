from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.threat_definitions.sources import bounded_https_fetch

FINGERPRINT_URL = "https://raw.githubusercontent.com/InfosecMatter/default-http-login-hunter/master/http-default-accounts-fingerprints-nndefaccts.lua"
SOURCE_REPOSITORY = "https://github.com/InfosecMatter/default-http-login-hunter"
UPSTREAM_DATASET = "https://github.com/nnposter/nndefaccts"
MAX_FINGERPRINT_BYTES = 2 * 1024 * 1024
MIN_FINGERPRINT_BYTES = 50 * 1024
APPROVED_FINGERPRINT_SHA256 = frozenset({
    # Reviewed live from the canonical repository on 2026-08-26.
    "54537fc4f401843e4d8564b3fc9299408b36c013c22727b45f778434d64ee87b",
})


@dataclass(frozen=True)
class FingerprintStatus:
    ready: bool
    path: str
    sha256: str
    size: int
    installed_at: str
    source_url: str = FINGERPRINT_URL
    license: str = "GNU GPL v3 or later (NNdefaccts; separately licensed from Nmap)"
    error: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class FingerprintManager:
    def __init__(
        self,
        root: Path,
        *,
        fetcher: Callable = bounded_https_fetch,
        approved_hashes: frozenset[str] = APPROVED_FINGERPRINT_SHA256,
    ) -> None:
        self.root = Path(root)
        self.path = self.root / "http-default-accounts-fingerprints-nndefaccts.lua"
        self.metadata_path = self.root / "fingerprints.json"
        self.fetcher = fetcher
        self.approved_hashes = frozenset(str(value).lower() for value in approved_hashes)

    def _require_approved_hash(self, digest: str) -> None:
        if not self.approved_hashes or digest.lower() not in self.approved_hashes:
            raise ValueError(
                "Fingerprint dataset SHA-256 is not an MSAA-reviewed upstream release; "
                "the existing validated dataset remains unchanged."
            )

    @staticmethod
    def _validate(payload: bytes) -> str:
        if not MIN_FINGERPRINT_BYTES <= len(payload) <= MAX_FINGERPRINT_BYTES:
            raise ValueError("Fingerprint dataset size is outside the approved bounds.")
        text = payload.decode("utf-8", "strict")
        required = (
            "This file is part of NNdefaccts",
            "local http = require \"http\"",
            "table.insert(fingerprints",
            "login_combos",
            "login_check",
        )
        if any(marker not in text for marker in required):
            raise ValueError("Fingerprint dataset is missing required NNdefaccts structure or attribution.")
        return hashlib.sha256(payload).hexdigest()

    def status(self) -> FingerprintStatus:
        try:
            if self.path.is_symlink() or not self.path.is_file():
                return FingerprintStatus(False, str(self.path), "", 0, "", error="Fingerprint dataset is not installed.")
            payload = self.path.read_bytes()
            digest = self._validate(payload)
            self._require_approved_hash(digest)
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8")) if self.metadata_path.is_file() else {}
            if metadata.get("sha256") and metadata.get("sha256") != digest:
                return FingerprintStatus(False, str(self.path), digest, len(payload), str(metadata.get("installed_at", "")), error="Fingerprint metadata hash mismatch.")
            return FingerprintStatus(True, str(self.path), digest, len(payload), str(metadata.get("installed_at", "")))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            return FingerprintStatus(False, str(self.path), "", 0, "", error=f"{type(exc).__name__}: {exc}")

    def install_or_update(self) -> FingerprintStatus:
        payload, content_type, metadata = self.fetcher(
            FINGERPRINT_URL, MAX_FINGERPRINT_BYTES,
            {"Accept": "text/plain"}, timeout_seconds=30, maximum_redirects=3,
        )
        digest = self._validate(payload)
        self._require_approved_hash(digest)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        temporary.write_bytes(payload)
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        record = {
            "schema_version": "1.0", "installed_at": utc_now_iso(), "source_url": FINGERPRINT_URL,
            "source_repository": SOURCE_REPOSITORY, "upstream_dataset": UPSTREAM_DATASET,
            "sha256": digest, "size": len(payload), "content_type": content_type,
            "etag": metadata.get("etag", ""), "last_modified": metadata.get("last-modified", ""),
            "license": "GNU GPL v3 or later",
        }
        metadata_temp = self.metadata_path.with_name(f".{self.metadata_path.name}.{os.getpid()}.tmp")
        metadata_temp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(metadata_temp, 0o600)
        os.replace(metadata_temp, self.metadata_path)
        return self.status()


__all__ = [
    "APPROVED_FINGERPRINT_SHA256",
    "FINGERPRINT_URL",
    "SOURCE_REPOSITORY",
    "UPSTREAM_DATASET",
    "FingerprintManager",
    "FingerprintStatus",
]
