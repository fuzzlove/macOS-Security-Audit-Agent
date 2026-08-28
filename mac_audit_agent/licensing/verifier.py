from __future__ import annotations

import base64
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import LicenseState, LicenseStatus
from .policy import DEFAULT_POLICY, LICENSE_SCHEMA_VERSION, LicensingPolicy


class LicenseVerificationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def signed_payload(document: Mapping[str, Any]) -> bytes:
    payload = dict(document)
    payload.pop("signature", None)
    return canonical_json(payload)


def _parse_time(value: object, field: str, *, required: bool = False) -> datetime | None:
    if value in (None, ""):
        if required:
            raise LicenseVerificationError("LIC_FIELD_REQUIRED", f"{field} is required")
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise LicenseVerificationError("LIC_TIME_INVALID", f"{field} must be an RFC3339 timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LicenseVerificationError("LIC_TIME_INVALID", f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise LicenseVerificationError("LIC_TIME_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _clean_text(value: object, field: str, *, required: bool = False, maximum: int = 256) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise LicenseVerificationError("LIC_FIELD_INVALID", f"{field} must be text")
    value = value.strip()
    if required and not value:
        raise LicenseVerificationError("LIC_FIELD_REQUIRED", f"{field} is required")
    if len(value) > maximum or any(ord(char) < 32 for char in value):
        raise LicenseVerificationError("LIC_FIELD_INVALID", f"{field} is invalid")
    return value


def load_trusted_keys(document: Mapping[str, Any]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for item in document.get("keys", []):
        if not isinstance(item, Mapping) or item.get("algorithm") != "Ed25519" or not item.get("enabled", True):
            continue
        key_id = _clean_text(item.get("key_id"), "key_id", required=True, maximum=128)
        try:
            raw = base64.b64decode(str(item.get("public_key", "")), validate=True)
        except (ValueError, TypeError) as exc:
            raise LicenseVerificationError("LIC_TRUST_STORE_INVALID", f"Invalid public key for {key_id}") from exc
        if len(raw) != 32:
            raise LicenseVerificationError("LIC_TRUST_STORE_INVALID", f"Ed25519 public key {key_id} is not 32 bytes")
        keys[key_id] = raw
    return keys


@dataclass(frozen=True)
class LicenseVerifier:
    trusted_keys: Mapping[str, bytes]
    policy: LicensingPolicy = DEFAULT_POLICY

    def verify(
        self,
        document: Mapping[str, Any],
        *,
        device_fingerprint: str,
        now: datetime | None = None,
        last_trusted_time: datetime | None = None,
    ) -> LicenseStatus:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        schema_version = document.get("schema_version")
        if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != LICENSE_SCHEMA_VERSION:
            raise LicenseVerificationError("LIC_SCHEMA_UNSUPPORTED", "Unsupported license schema version")
        if _clean_text(document.get("product_id"), "product_id", required=True) != self.policy.product_id:
            raise LicenseVerificationError("LIC_PRODUCT_MISMATCH", "License is for a different product")

        signature = document.get("signature")
        if not isinstance(signature, Mapping) or signature.get("algorithm") != "Ed25519":
            raise LicenseVerificationError("LIC_SIGNATURE_INVALID", "An Ed25519 signature is required")
        key_id = _clean_text(signature.get("key_id"), "signature.key_id", required=True, maximum=128)
        public_key = self.trusted_keys.get(key_id)
        if public_key is None:
            raise LicenseVerificationError("LIC_KEY_UNKNOWN", "License signing key is not trusted")
        try:
            signature_bytes = base64.b64decode(str(signature.get("value", "")), validate=True)
        except (ValueError, TypeError) as exc:
            raise LicenseVerificationError("LIC_SIGNATURE_INVALID", "License signature is malformed") from exc
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, signed_payload(document))
        except ImportError as exc:
            raise LicenseVerificationError("LIC_VERIFIER_UNAVAILABLE", "Install MSAA's crypto dependency to verify licenses") from exc
        except Exception as exc:
            raise LicenseVerificationError("LIC_SIGNATURE_INVALID", "License signature verification failed") from exc

        license_id = _clean_text(document.get("license_id"), "license_id", required=True, maximum=128)
        edition = _clean_text(document.get("edition"), "edition", required=True, maximum=64).upper()
        licensed_to = _clean_text(document.get("licensed_to"), "licensed_to", maximum=256)
        issued = _parse_time(document.get("issued_at"), "issued_at", required=True)
        not_before = _parse_time(document.get("not_before"), "not_before") or issued
        expires = _parse_time(document.get("expires_at"), "expires_at")
        maintenance = _parse_time(document.get("maintenance_until"), "maintenance_until")
        activation_mode = _clean_text(document.get("activation_mode", "offline"), "activation_mode", maximum=32)
        features_value = document.get("features", [])
        if not isinstance(features_value, list) or len(features_value) > 256:
            raise LicenseVerificationError("LIC_FEATURES_INVALID", "features must be a bounded list")
        features = tuple(sorted({_clean_text(item, "feature", required=True, maximum=128) for item in features_value}))
        binding = document.get("device_binding") or {}
        if not isinstance(binding, Mapping):
            raise LicenseVerificationError("LIC_BINDING_INVALID", "device_binding must be an object")
        expected_fingerprint = _clean_text(binding.get("fingerprint", ""), "device_binding.fingerprint", maximum=128)
        if expected_fingerprint and (len(expected_fingerprint) != 64 or any(char not in "0123456789abcdef" for char in expected_fingerprint)):
            raise LicenseVerificationError("LIC_BINDING_INVALID", "Device fingerprint must be 64 lowercase hexadecimal characters")
        if expected_fingerprint and expected_fingerprint != device_fingerprint:
            return LicenseStatus(
                state=LicenseState.DEVICE_MISMATCH,
                message="This license is bound to a different MSAA installation.",
                license_id=license_id,
                edition=edition,
                licensed_to=licensed_to,
                issued_at=issued.isoformat(),
                expires_at=expires.isoformat() if expires else None,
                features=features,
                activation_mode=activation_mode,
                device_bound=True,
                key_id=key_id,
                error_code="LIC_DEVICE_MISMATCH",
            )

        common = {
            "license_id": license_id,
            "edition": edition,
            "licensed_to": licensed_to,
            "issued_at": issued.isoformat(),
            "expires_at": expires.isoformat() if expires else None,
            "maintenance_until": maintenance.isoformat() if maintenance else None,
            "features": features,
            "activation_mode": activation_mode,
            "device_bound": bool(expected_fingerprint),
            "key_id": key_id,
            "last_verified_at": now.isoformat(),
        }
        if last_trusted_time and now.timestamp() + self.policy.clock_rollback_tolerance_seconds < last_trusted_time.timestamp():
            return LicenseStatus(
                state=LicenseState.CLOCK_ROLLBACK_SUSPECTED,
                message="The system clock moved behind the last trusted license check. Verify date and time.",
                error_code="LIC_CLOCK_ROLLBACK",
                warnings=("Core security protection remains operational while licensing requires review.",),
                **common,
            )
        if now < not_before:
            return LicenseStatus(state=LicenseState.NOT_YET_VALID, message="The license validity period has not started.", error_code="LIC_NOT_YET_VALID", **common)
        if expires and now >= expires:
            return LicenseStatus(
                state=LicenseState.EXPIRED,
                message="The product license has expired. Core protection and evidence preservation remain active.",
                days_remaining=0,
                error_code="LIC_EXPIRED",
                warnings=("Commercial premium features are unavailable until a valid license is installed.",),
                **common,
            )
        days = math.ceil((expires - now).total_seconds() / 86400) if expires else None
        if days is not None and days <= self.policy.expiring_warning_days:
            return LicenseStatus(
                state=LicenseState.EXPIRING,
                message=f"License is valid and expires in {days} day{'s' if days != 1 else ''}.",
                days_remaining=days,
                warnings=("Renew before expiration to preserve commercial premium feature access.",),
                **common,
            )
        return LicenseStatus(state=LicenseState.VALID, message="License signature and validity checks passed.", days_remaining=days, **common)
