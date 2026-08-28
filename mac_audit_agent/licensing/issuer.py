from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .policy import (
    LICENSE_SCHEMA_VERSION,
    PRODUCT_ID,
    PROVISIONAL_LICENSOR,
)
from .verifier import signed_payload


class LicenseIssuanceError(ValueError):
    """Raised when the server-side issuer configuration or grant is invalid."""


def _bounded_text(value: str, field: str, maximum: int = 256) -> str:
    cleaned = str(value).strip()
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise LicenseIssuanceError(f"{field} is invalid")
    return cleaned


@dataclass(frozen=True)
class LicenseIssuer:
    """Server-side Ed25519 issuer. Private key material is never exported."""

    private_key: object
    key_id: str
    issuer_name: str = PROVISIONAL_LICENSOR

    @classmethod
    def from_pem(
        cls,
        path: Path,
        *,
        key_id: str,
        password: str | None = None,
        maximum_bytes: int = 65_536,
    ) -> LicenseIssuer:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_path = path.expanduser()
        if not private_path.is_file() or private_path.stat().st_size > maximum_bytes:
            raise LicenseIssuanceError("The license signing key is missing or oversized")
        key = serialization.load_pem_private_key(
            private_path.read_bytes(),
            password=password.encode("utf-8") if password else None,
        )
        if not isinstance(key, Ed25519PrivateKey):
            raise LicenseIssuanceError("The license signing key must be Ed25519")
        return cls(key, _bounded_text(key_id, "key_id", 128))

    def issue(
        self,
        *,
        license_id: str,
        licensed_to: str,
        device_fingerprint: str,
        expires_at: datetime,
        features: tuple[str, ...],
        edition: str = "COMMERCIAL",
        activation_mode: str = "stripe",
        now: datetime | None = None,
    ) -> dict:
        issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        expiry = expires_at.astimezone(timezone.utc)
        if expiry <= issued_at:
            raise LicenseIssuanceError("Cannot issue an already-expired license")
        fingerprint = str(device_fingerprint).strip()
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise LicenseIssuanceError("device_fingerprint must be 64 lowercase hexadecimal characters")
        feature_values = tuple(sorted({_bounded_text(item, "feature", 128).lower() for item in features}))
        document = {
            "schema_version": LICENSE_SCHEMA_VERSION,
            "product_id": PRODUCT_ID,
            "license_id": _bounded_text(license_id, "license_id", 128),
            "edition": _bounded_text(edition, "edition", 64).upper(),
            "licensed_to": _bounded_text(licensed_to, "licensed_to", 256),
            "issuer": _bounded_text(self.issuer_name, "issuer", 256),
            "issued_at": issued_at.isoformat(),
            "not_before": (issued_at - timedelta(minutes=5)).isoformat(),
            "expires_at": expiry.isoformat(),
            "maintenance_until": expiry.isoformat(),
            "activation_mode": _bounded_text(activation_mode, "activation_mode", 32).lower(),
            "features": list(feature_values),
            "device_binding": {"fingerprint": fingerprint},
        }
        signature = self.private_key.sign(signed_payload(document))
        document["signature"] = {
            "algorithm": "Ed25519",
            "key_id": self.key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        }
        return document
