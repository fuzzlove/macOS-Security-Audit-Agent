"""Detached Ed25519 manifest signatures with an out-of-band trust store."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class SignatureError(ValueError):
    pass


def canonical_json(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class SignatureEnvelope:
    key_id: str
    algorithm: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {"key_id": self.key_id, "algorithm": self.algorithm, "signature": self.signature}


class ManifestSigner:
    def __init__(self, key_id: str, signer: Callable[[bytes], bytes]) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key_id):
            raise ValueError("invalid signing key id")
        self.key_id = key_id
        self._signer = signer

    def sign(self, manifest: dict) -> SignatureEnvelope:
        return SignatureEnvelope(self.key_id, "Ed25519", base64.b64encode(self._signer(canonical_json(manifest))).decode("ascii"))


class ManifestTrustStore:
    """Loads only administrator-provisioned PEM keys; bundles cannot extend trust."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def verify(self, manifest: dict, envelope: dict) -> str:
        key_id = str(envelope.get("key_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key_id):
            raise SignatureError("manifest signature key id is invalid")
        if envelope.get("algorithm") != "Ed25519":
            raise SignatureError("only Ed25519 definition signatures are accepted")
        key_path = self.root / f"{key_id}.pem"
        if not key_path.is_file() or key_path.is_symlink() or key_path.stat().st_size > 16_384:
            raise SignatureError("definition signing key is not trusted")
        try:
            signature = base64.b64decode(str(envelope.get("signature", "")), validate=True)
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            key = load_pem_public_key(key_path.read_bytes())
            key.verify(signature, canonical_json(manifest))
        except Exception as exc:
            raise SignatureError("definition manifest signature is invalid") from exc
        return key_id


__all__ = ["ManifestSigner", "ManifestTrustStore", "SignatureEnvelope", "SignatureError", "canonical_json"]
