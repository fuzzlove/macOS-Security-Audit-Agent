from __future__ import annotations

import base64
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pytest

from mac_audit_agent.licensing.activation import (
    ActivationClient,
    ActivationError,
    _service_http_error,
    _validate_activation_url,
)
from mac_audit_agent.licensing.checkout import CheckoutClient
from mac_audit_agent.licensing.manager import LicenseManager
from mac_audit_agent.licensing.models import LicenseFeature, LicenseState
from mac_audit_agent.licensing.policy import (
    DEFAULT_LICENSE_ACTIVATION_URL,
    DEFAULT_LICENSE_CHECKOUT_URL,
    OFFLINE_LICENSE_CONTACT,
    OFFLINE_LICENSE_PRICE_USD,
    OFFLINE_LICENSE_TERM,
)
from mac_audit_agent.licensing.registration import service_registration_license_decision
from mac_audit_agent.licensing.storage import LicenseStorage
from mac_audit_agent.licensing.verifier import (
    LicenseVerificationError,
    canonical_json,
    signed_payload,
)

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _manager(tmp_path: Path) -> tuple[LicenseManager, Ed25519PrivateKey]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return LicenseManager(storage=LicenseStorage(tmp_path / "licensing"), trusted_keys={"test-key": public}), private


def _document(manager: LicenseManager, private: Ed25519PrivateKey, **changes) -> dict:
    now = datetime.now(timezone.utc)
    document = {
        "schema_version": 1,
        "product_id": manager.policy.product_id,
        "license_id": "MSAA-TEST-0001",
        "edition": "COMMERCIAL",
        "licensed_to": "Example Defensive Team",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=365)).isoformat(),
        "maintenance_until": (now + timedelta(days=365)).isoformat(),
        "activation_mode": "offline",
        "features": ["professional_reports", "commercial_use"],
        "device_binding": {"fingerprint": manager.device_fingerprint()},
    }
    document.update(changes)
    document["signature"] = {
        "algorithm": "Ed25519",
        "key_id": "test-key",
        "value": base64.b64encode(private.sign(signed_payload(document))).decode("ascii"),
    }
    return document


def _write(path: Path, document: dict) -> None:
    path.write_bytes(canonical_json(document) + b"\n")


def test_signed_offline_license_import_and_feature_enforcement(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    source = tmp_path / "license.json"
    _write(source, _document(manager, private))

    status = manager.import_offline(source)

    assert status.state is LicenseState.VALID
    assert manager.product_access(status)["mode"] == "LICENSED"
    assert manager.product_access(status)["operator_actions_enabled"] is True
    assert manager.is_feature_available(LicenseFeature.PROFESSIONAL_REPORTS)
    assert not manager.is_feature_available(LicenseFeature.ENTERPRISE_INTEGRATIONS)
    assert manager.is_feature_available(LicenseFeature.CORE_PROTECTION)
    stored = manager.storage.read_license(manager.policy.maximum_document_bytes)
    assert stored and stored["license_id"] == "MSAA-TEST-0001"


def test_demo_preview_explains_how_to_request_an_offline_license(tmp_path: Path) -> None:
    manager, _private = _manager(tmp_path)

    access = manager.product_access()

    assert access["mode"] == "DEMO_PREVIEW"
    assert access["operator_actions_enabled"] is False
    assert OFFLINE_LICENSE_CONTACT in access["reason"]
    assert f"${OFFLINE_LICENSE_PRICE_USD}/{OFFLINE_LICENSE_TERM}" in access["reason"]
    assert "$10/month" in access["reason"]


def test_service_registration_requires_valid_commercial_activation(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)

    unlicensed = service_registration_license_decision(tmp_path, manager=manager)
    assert unlicensed.allowed is False
    assert unlicensed.code == "LIC_NOT_INSTALLED"

    manager.storage.store_verified_license(_document(manager, private, activation_mode="stripe"))
    licensed = service_registration_license_decision(tmp_path, manager=manager)
    assert licensed.allowed is True
    assert licensed.license_state == "VALID"
    assert licensed.activation_mode == "stripe"


def test_tampered_license_is_rejected_without_replacing_active(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    good = tmp_path / "good.json"
    _write(good, _document(manager, private))
    assert manager.import_offline(good).valid
    before = manager.storage.license_path.read_bytes()
    tampered = _document(manager, private)
    tampered["edition"] = "UNAUTHORIZED-TAMPER"
    bad = tmp_path / "bad.json"
    _write(bad, tampered)

    with pytest.raises(LicenseVerificationError, match="signature"):
        manager.import_offline(bad)

    assert manager.storage.license_path.read_bytes() == before
    assert manager.status().valid


def test_expired_license_keeps_core_security_but_gates_premium(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    now = datetime.now(timezone.utc)
    source = tmp_path / "expired.json"
    _write(source, _document(manager, private, expires_at=(now - timedelta(seconds=1)).isoformat()))
    document = json.loads(source.read_text())
    document["signature"]["value"] = base64.b64encode(private.sign(signed_payload(document))).decode("ascii")
    _write(source, document)
    result = manager.verifier.verify(document, device_fingerprint=manager.device_fingerprint())

    assert result.state is LicenseState.EXPIRED
    assert manager.is_feature_available(LicenseFeature.CORE_PROTECTION)
    assert not manager.is_feature_available(LicenseFeature.PROFESSIONAL_REPORTS)


def test_device_binding_mismatch_is_explicit(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    document = _document(manager, private, device_binding={"fingerprint": "0" * 64})
    document["signature"]["value"] = base64.b64encode(private.sign(signed_payload(document))).decode("ascii")
    result = manager.verifier.verify(document, device_fingerprint=manager.device_fingerprint())
    assert result.state is LicenseState.DEVICE_MISMATCH
    assert result.error_code == "LIC_DEVICE_MISMATCH"


def test_unknown_signing_key_and_malformed_signature_are_rejected(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    document = _document(manager, private)
    document["signature"]["key_id"] = "unknown"
    with pytest.raises(LicenseVerificationError) as error:
        manager.verifier.verify(document, device_fingerprint=manager.device_fingerprint())
    assert error.value.code == "LIC_KEY_UNKNOWN"


def test_revoked_license_is_rejected_without_disabling_core_security(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    manager.revoked_license_ids = frozenset({"MSAA-TEST-0001"})
    source = tmp_path / "revoked.json"
    _write(source, _document(manager, private))

    result = manager.import_offline(source)

    assert result.state is LicenseState.INVALID
    assert result.error_code == "LIC_REVOKED"
    assert manager.is_feature_available(LicenseFeature.CORE_PROTECTION)


def test_clock_rollback_is_reported(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    document = _document(manager, private)
    now = datetime.now(timezone.utc)
    result = manager.verifier.verify(
        document,
        device_fingerprint=manager.device_fingerprint(),
        now=now,
        last_trusted_time=now + timedelta(hours=2),
    )
    assert result.state is LicenseState.CLOCK_ROLLBACK_SUSPECTED


def test_storage_rejects_symlink_license(tmp_path: Path) -> None:
    storage = LicenseStorage(tmp_path / "licensing")
    storage.root.mkdir()
    target = tmp_path / "target.json"
    target.write_text("{}")
    storage.license_path.symlink_to(target)
    with pytest.raises(OSError, match="symbolic"):
        storage.read_license(1024)


def test_activation_rejects_insecure_and_private_endpoints() -> None:
    with pytest.raises(ActivationError):
        _validate_activation_url("http://licenses.example.com/activate", allow_private_hosts=False)
    with pytest.raises(ActivationError):
        _validate_activation_url("https://localhost/activate", allow_private_hosts=False)
    with pytest.raises(ActivationError):
        _validate_activation_url("https://licenses.example.com/activate#fragment", allow_private_hosts=False)
    parsed = _validate_activation_url(
        "https://checkout.stripe.com/c/pay/test#stripe-client-state",
        allow_private_hosts=True,
        allow_fragment=True,
    )
    assert parsed.fragment == "stripe-client-state"


def test_activation_preserves_bounded_service_error_codes() -> None:
    body = json.dumps({"error_code": "LIC_PAYMENT_PENDING", "message": "Payment is still pending."}).encode()
    response = urllib.error.HTTPError(
        "https://licenses.example.test/v1/activate",
        409,
        "Conflict",
        {},
        BytesIO(body),
    )

    error = _service_http_error(response, 4096)

    assert error.code == "LIC_PAYMENT_PENDING"
    assert str(error) == "Payment is still pending."


def test_online_activation_stores_only_a_verified_signed_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager, private = _manager(tmp_path)
    document = _document(manager, private, activation_mode="online")
    document["signature"]["value"] = base64.b64encode(private.sign(signed_payload(document))).decode("ascii")
    captured: dict[str, str] = {}

    def fake_activate(_client: ActivationClient, code: str, payload: dict) -> dict:
        captured["code"] = code
        captured["product_id"] = payload["product_id"]
        return document

    monkeypatch.setattr(ActivationClient, "activate", fake_activate)
    result = manager.activate_online("one-time-secret", endpoint="https://licenses.example.test/v1/activate")

    assert result.valid
    assert result.activation_mode == "online"
    assert manager.product_access(result)["mode"] == "DEMO_PREVIEW"
    assert manager.product_access(result)["operator_actions_enabled"] is False
    assert captured == {"code": "one-time-secret", "product_id": manager.policy.product_id}
    assert "one-time-secret" not in manager.storage.audit_path.read_text()


def test_manager_creates_stripe_checkout_for_its_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager, _private = _manager(tmp_path)
    captured: dict[str, str] = {}

    def fake_begin(_client: CheckoutClient, **payload: str) -> dict:
        captured.update(payload)
        return {
            "checkout_url": "https://checkout.stripe.com/c/pay/test",
            "activation_code": "MSAA-ACT-1.test.signature",
            "checkout_host": "licenses.example.test",
        }

    monkeypatch.setattr(CheckoutClient, "begin", fake_begin)
    result = manager.begin_stripe_checkout(
        endpoint="https://licenses.example.test/v1/checkout",
        customer_email="buyer@example.test",
        licensed_to="Example Buyer",
    )

    assert result["checkout_url"].startswith("https://checkout.stripe.com/")
    assert captured == {
        "product_id": manager.policy.product_id,
        "device_fingerprint": manager.device_fingerprint(),
        "customer_email": "buyer@example.test",
        "licensed_to": "Example Buyer",
    }


def test_manager_uses_bundled_liquidsky_checkout_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager, _private = _manager(tmp_path)
    captured: dict[str, str] = {}
    monkeypatch.delenv("MSAA_LICENSE_CHECKOUT_URL", raising=False)
    monkeypatch.delenv("MSAA_LICENSE_ACTIVATION_URL", raising=False)

    def fake_begin(client: CheckoutClient, **_payload: str) -> dict:
        captured["endpoint"] = client.endpoint
        return {
            "checkout_url": "https://checkout.stripe.com/c/pay/test",
            "activation_code": "MSAA-ACT-1.test.signature",
            "checkout_host": "licenses.liquidskysecurity.com",
        }

    monkeypatch.setattr(CheckoutClient, "begin", fake_begin)

    manager.begin_stripe_checkout()
    doctor = manager.doctor()

    assert captured["endpoint"] == DEFAULT_LICENSE_CHECKOUT_URL
    assert DEFAULT_LICENSE_ACTIVATION_URL.endswith("/v1/activate")
    assert doctor["stripe_checkout_endpoint_configured"] is True
    assert doctor["activation_endpoint_configured"] is True


def test_stripe_signed_license_unlocks_product_access(tmp_path: Path) -> None:
    manager, private = _manager(tmp_path)
    source = tmp_path / "stripe-license.json"
    document = _document(manager, private, activation_mode="stripe")
    document["signature"]["value"] = base64.b64encode(private.sign(signed_payload(document))).decode("ascii")
    _write(source, document)

    status = manager.import_offline(source)

    assert status.valid
    assert manager.product_access(status)["mode"] == "LICENSED"
    assert manager.product_access(status)["operator_actions_enabled"] is True


def test_audit_log_does_not_store_secrets(tmp_path: Path) -> None:
    storage = LicenseStorage(tmp_path / "licensing")
    storage.audit("LICENSE_ACTIVATE", "REJECTED", activation_code="secret-code", error_code="TEST")
    text = storage.audit_path.read_text()
    assert "secret-code" not in text
    assert "activation_code" not in text
    assert "record_hash" in text
    assert storage.verify_audit_chain()["status"] == "VALID"
