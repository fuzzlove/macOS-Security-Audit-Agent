from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .activation import ActivationClient, ActivationError
from .checkout import CheckoutClient
from .models import LicenseState, LicenseStatus
from .policy import (
    DEFAULT_LICENSE_ACTIVATION_URL,
    DEFAULT_LICENSE_CHECKOUT_URL,
    DEFAULT_POLICY,
    OFFLINE_LICENSE_CONTACT,
    OFFLINE_LICENSE_PRICE_USD,
    OFFLINE_LICENSE_TERM,
    LicensingPolicy,
)
from .storage import LicenseStorage
from .verifier import LicenseVerificationError, LicenseVerifier, load_trusted_keys


def _default_trust_store_path() -> Path:
    configured = os.environ.get("MSAA_LICENSE_TRUST_STORE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent.parent / "assets" / "licensing" / "trusted_license_keys.json"


class LicenseManager:
    def __init__(
        self,
        *,
        storage: LicenseStorage | None = None,
        policy: LicensingPolicy = DEFAULT_POLICY,
        trusted_keys: Mapping[str, bytes] | None = None,
        revoked_license_ids: set[str] | None = None,
        trust_store_path: Path | None = None,
    ) -> None:
        self.storage = storage or LicenseStorage()
        self.policy = policy
        if trusted_keys is None:
            path = trust_store_path or _default_trust_store_path()
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise TypeError("License trust store must contain a JSON object")
                trusted_keys = load_trusted_keys(value)
                if revoked_license_ids is None:
                    revoked = value.get("revoked_license_ids", [])
                    revoked_license_ids = {str(item).strip() for item in revoked if isinstance(item, str) and item.strip()} if isinstance(revoked, list) else set()
            except FileNotFoundError:
                trusted_keys = {}
        self.revoked_license_ids = frozenset(revoked_license_ids or set())
        self.verifier = LicenseVerifier(dict(trusted_keys), policy)

    def _audit(self, action: str, result: str, **details: Any) -> bool:
        try:
            self.storage.audit(action, result, **details)
            return True
        except OSError:
            return False

    def _apply_revocation(self, status: LicenseStatus) -> LicenseStatus:
        if status.license_id and status.license_id in self.revoked_license_ids:
            return LicenseStatus(
                LicenseState.INVALID,
                "The installed product license has been revoked by the trusted MSAA license authority.",
                license_id=status.license_id,
                edition=status.edition,
                licensed_to=status.licensed_to,
                issued_at=status.issued_at,
                expires_at=status.expires_at,
                maintenance_until=status.maintenance_until,
                features=status.features,
                activation_mode=status.activation_mode,
                device_bound=status.device_bound,
                key_id=status.key_id,
                last_verified_at=status.last_verified_at,
                error_code="LIC_REVOKED",
                warnings=("Core security protection and evidence preservation remain operational.",),
            )
        return status

    def device_fingerprint(self) -> str:
        return self.storage.device_fingerprint(self.policy.product_id)

    def status(self, *, now: datetime | None = None) -> LicenseStatus:
        try:
            document = self.storage.read_license(self.policy.maximum_document_bytes)
        except (OSError, ValueError, TypeError) as exc:
            return LicenseStatus(LicenseState.INVALID, "Stored license could not be read safely.", error_code="LIC_STORAGE_INVALID", metadata={"error_type": type(exc).__name__})
        if document is None:
            return LicenseStatus(
                LicenseState.UNLICENSED,
                "No signed product license is installed. Core protection and evidence preservation remain active.",
                warnings=("Commercial premium features require activation.",),
                error_code="LIC_NOT_INSTALLED",
            )
        state = self.storage.read_state()
        last_trusted: datetime | None = None
        if state.get("last_trusted_time"):
            try:
                last_trusted = datetime.fromisoformat(str(state["last_trusted_time"]))
            except ValueError:
                last_trusted = None
        try:
            result = self._apply_revocation(self.verifier.verify(document, device_fingerprint=self.device_fingerprint(), now=now, last_trusted_time=last_trusted))
        except LicenseVerificationError as exc:
            state_kind = LicenseState.VERIFIER_UNAVAILABLE if exc.code == "LIC_VERIFIER_UNAVAILABLE" else LicenseState.INVALID
            self._audit("LICENSE_VERIFY", "REJECTED", error_code=exc.code)
            return LicenseStatus(state_kind, str(exc), error_code=exc.code)
        except OSError as exc:
            return LicenseStatus(LicenseState.INVALID, "The installation identity could not be read safely.", error_code="LIC_DEVICE_ID_UNAVAILABLE", metadata={"error_type": type(exc).__name__})
        if result.state in {LicenseState.VALID, LicenseState.EXPIRING, LicenseState.EXPIRED, LicenseState.NOT_YET_VALID}:
            verified_at = result.last_verified_at or datetime.now(timezone.utc).isoformat()
            try:
                self.storage.write_state({"last_trusted_time": verified_at, "license_id": result.license_id, "state": result.state.value})
            except OSError:
                self._audit("LICENSE_STATE_WRITE", "FAILED", license_id=result.license_id)
        return result

    def import_offline(self, source: Path) -> LicenseStatus:
        candidate = source.expanduser()
        if candidate.is_symlink():
            raise LicenseVerificationError("LIC_IMPORT_REJECTED", "Offline license may not be a symbolic link")
        path = candidate.resolve(strict=True)
        if not path.is_file() or path.stat().st_size > self.policy.maximum_document_bytes:
            raise LicenseVerificationError("LIC_IMPORT_REJECTED", "Offline license is not a safe bounded regular file")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise LicenseVerificationError("LIC_IMPORT_INVALID", "Offline license is not valid UTF-8 JSON") from exc
        if not isinstance(document, dict):
            raise LicenseVerificationError("LIC_IMPORT_INVALID", "Offline license must contain a JSON object")
        result = self._apply_revocation(self.verifier.verify(document, device_fingerprint=self.device_fingerprint()))
        if not result.valid:
            self._audit("LICENSE_IMPORT", "REJECTED", state=result.state.value, error_code=result.error_code)
            return result
        self.storage.store_verified_license(document)
        self._audit("LICENSE_IMPORT", "ACCEPTED", license_id=result.license_id, edition=result.edition)
        return self.status()

    def activate_online(self, activation_code: str, *, endpoint: str | None = None) -> LicenseStatus:
        activation_endpoint = (
            endpoint
            or os.environ.get("MSAA_LICENSE_ACTIVATION_URL", "")
            or DEFAULT_LICENSE_ACTIVATION_URL
        ).strip()
        if not activation_endpoint:
            raise ActivationError("LIC_ACTIVATION_NOT_CONFIGURED", "No MSAA license activation endpoint is configured")
        payload = {
            "product_id": self.policy.product_id,
            "device_fingerprint": self.device_fingerprint(),
            "request_nonce": secrets.token_urlsafe(24),
            "client_time": datetime.now(timezone.utc).isoformat(),
        }
        document = ActivationClient(activation_endpoint, self.policy).activate(activation_code, payload)
        result = self._apply_revocation(self.verifier.verify(document, device_fingerprint=self.device_fingerprint()))
        if not result.valid:
            self._audit("LICENSE_ACTIVATE", "REJECTED", state=result.state.value, error_code=result.error_code)
            return result
        self.storage.store_verified_license(document)
        self._audit("LICENSE_ACTIVATE", "ACCEPTED", license_id=result.license_id, edition=result.edition)
        return self.status()

    def begin_stripe_checkout(
        self,
        *,
        endpoint: str | None = None,
        customer_email: str = "",
        licensed_to: str = "",
    ) -> dict[str, Any]:
        checkout_endpoint = (
            endpoint
            or os.environ.get("MSAA_LICENSE_CHECKOUT_URL", "")
            or DEFAULT_LICENSE_CHECKOUT_URL
        ).strip()
        if not checkout_endpoint:
            raise ActivationError("LIC_CHECKOUT_NOT_CONFIGURED", "No MSAA Stripe Checkout endpoint is configured")
        result = CheckoutClient(checkout_endpoint, self.policy).begin(
            product_id=self.policy.product_id,
            device_fingerprint=self.device_fingerprint(),
            customer_email=customer_email,
            licensed_to=licensed_to,
        )
        self._audit("LICENSE_CHECKOUT", "CREATED", checkout_host=result.get("checkout_host", ""))
        return result

    def is_feature_available(self, feature: str) -> bool:
        normalized = str(getattr(feature, "value", feature)).strip().lower()
        if normalized in self.policy.core_safety_features:
            return True
        status = self.status()
        access = self.product_access(status)
        return bool(access["operator_actions_enabled"]) and (normalized in status.features or "*" in status.features)

    def product_access(self, status: LicenseStatus | None = None) -> dict[str, Any]:
        current = status or self.status()
        licensed = current.valid and current.activation_mode in self.policy.operator_unlock_activation_modes
        return {
            "mode": "LICENSED" if licensed else "DEMO_PREVIEW",
            "operator_actions_enabled": licensed,
            "content_preview_enabled": True,
            "required_activation_modes": sorted(self.policy.operator_unlock_activation_modes),
            "license_state": current.state.value,
            "activation_mode": current.activation_mode,
            "core_background_safety_preserved": True,
            "reason": (
                "A valid signed MSAA license enables operational controls."
                if licensed
                else (
                    "Demo Preview is active. Purchase with Stripe or import a valid signed offline license to enable operational controls. "
                    f"Licenses are ${OFFLINE_LICENSE_PRICE_USD}/{OFFLINE_LICENSE_TERM}; contact {OFFLINE_LICENSE_CONTACT} if online checkout is unavailable."
                )
            ),
        }

    def feature_decision(self, feature: str) -> dict[str, Any]:
        normalized = str(getattr(feature, "value", feature)).strip().lower()
        status = self.status()
        access = self.product_access(status)
        available = normalized in self.policy.core_safety_features or (
            bool(access["operator_actions_enabled"]) and (normalized in status.features or "*" in status.features)
        )
        return {
            "feature": normalized,
            "available": available,
            "license_state": status.state.value,
            "product_access_mode": access["mode"],
            "core_safety_feature": normalized in self.policy.core_safety_features,
            "reason": "Core security capability remains available regardless of license state." if normalized in self.policy.core_safety_features else ("Granted by the active signed license." if available else "A valid license granting this commercial feature is required."),
        }

    def doctor(self) -> dict[str, Any]:
        status = self.status()
        return {
            "status": "PASS" if status.valid else "ATTENTION",
            "license": status.to_dict(),
            "storage_root": str(self.storage.root),
            "storage_exists": self.storage.root.exists(),
            "trust_keys_loaded": len(self.verifier.trusted_keys),
            "revoked_license_ids_loaded": len(self.revoked_license_ids),
            "device_fingerprint": self.device_fingerprint(),
            "activation_endpoint_configured": bool(
                os.environ.get("MSAA_LICENSE_ACTIVATION_URL", "").strip()
                or DEFAULT_LICENSE_ACTIVATION_URL
            ),
            "stripe_checkout_endpoint_configured": bool(
                os.environ.get("MSAA_LICENSE_CHECKOUT_URL", "").strip()
                or DEFAULT_LICENSE_CHECKOUT_URL
            ),
            "private_signing_key_present_in_application": False,
            "audit_chain": self.storage.verify_audit_chain(),
            "product_access": self.product_access(status),
        }
