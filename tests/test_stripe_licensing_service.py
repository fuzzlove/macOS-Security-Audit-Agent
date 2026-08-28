from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pytest

from mac_audit_agent.licensing.issuer import LicenseIssuer
from mac_audit_agent.licensing.policy import PRODUCT_ID
from mac_audit_agent.licensing.stripe_service import (
    OrderStore,
    StripeLicensingConfig,
    StripeLicensingError,
    StripeLicensingService,
    StripeLicensingWSGIApp,
    _plain,
)
from mac_audit_agent.licensing.verifier import LicenseVerifier

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class FakeStripeGateway:
    def __init__(self) -> None:
        self.created_params: dict = {}
        self.session: dict = {}
        self.subscription: dict = {}
        self.session_retrievals = 0

    def create_checkout_session(self, params: dict, *, idempotency_key: str) -> dict:
        self.created_params = params
        self.session = {
            "id": "cs_test_msaa",
            "url": "https://checkout.stripe.com/c/pay/cs_test_msaa#stripe-client-state",
            "livemode": False,
            "payment_status": "unpaid",
        }
        assert idempotency_key.startswith("msaa-checkout-")
        return self.session

    def retrieve_checkout_session(self, session_id: str) -> dict:
        self.session_retrievals += 1
        assert session_id == self.session["id"]
        return self.session

    def retrieve_subscription(self, subscription_id: str) -> dict:
        assert subscription_id == self.subscription["id"]
        return self.subscription

    def construct_webhook_event(self, payload: bytes, signature: str, secret: str) -> dict:
        import json

        assert signature == "valid-test-signature"
        assert secret == "whsec_test"
        return json.loads(payload)


class StripeV15Resource:
    def to_dict(self) -> dict:
        return {"id": "cs_test_v15", "nested": StripeV15NestedResource()}


class StripeV15NestedResource:
    def to_dict(self) -> dict:
        return {"livemode": False}


def test_plain_supports_stripe_v15_to_dict_resources() -> None:
    assert _plain(StripeV15Resource()) == {
        "id": "cs_test_v15",
        "nested": {"livemode": False},
    }


def _service(
    tmp_path: Path,
    *,
    checkout_mode: str = "subscription",
) -> tuple[StripeLicensingService, FakeStripeGateway, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    config = StripeLicensingConfig(
        stripe_secret_key="sk_test_placeholder",
        webhook_secret="whsec_test",
        price_id="price_msaa_monthly",
        success_url="https://licenses.example.test/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://licenses.example.test/cancel",
        database_path=tmp_path / "orders.sqlite3",
        private_key_path=tmp_path / "unused.pem",
        signing_key_id="test-key",
        activation_token_secret=b"a" * 32,
        checkout_mode=checkout_mode,
    )
    gateway = FakeStripeGateway()
    service = StripeLicensingService(
        config,
        gateway=gateway,
        store=OrderStore(config.database_path),
        issuer=LicenseIssuer(private, "test-key"),
    )
    return service, gateway, public


def _checkout(service: StripeLicensingService) -> dict:
    return service.create_checkout(
        {
            "product_id": PRODUCT_ID,
            "device_fingerprint": "1" * 64,
            "request_nonce": "request-nonce-with-enough-entropy",
        }
    )


def _paid_session(service: StripeLicensingService, gateway: FakeStripeGateway, order_id: str) -> int:
    period_end = int((datetime.now(timezone.utc) + timedelta(days=31)).timestamp())
    gateway.session = {
        "id": "cs_test_msaa",
        "livemode": False,
        "payment_status": "paid",
        "client_reference_id": order_id,
        "metadata": {"msaa_order_id": order_id, "msaa_product_id": PRODUCT_ID},
        "customer": "cus_test",
        "customer_details": {"email": "buyer@example.test", "name": "Example Buyer"},
        "subscription": "sub_test",
        "line_items": {"data": [{"price": {"id": service.config.price_id}}]},
    }
    gateway.subscription = {
        "id": "sub_test",
        "status": "active",
        "items": {
            "data": [
                {
                    "price": {"id": service.config.price_id},
                    "current_period_end": period_end,
                }
            ]
        },
    }
    return period_end


def _event(event_id: str, event_type: str, value: dict) -> bytes:
    import json

    return json.dumps(
        {
            "id": event_id,
            "type": event_type,
            "livemode": False,
            "data": {"object": value},
        }
    ).encode()


def _wsgi_get(app: StripeLicensingWSGIApp, path: str) -> tuple[str, dict[str, str], bytes]:
    response_status = ""
    response_headers: dict[str, str] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        nonlocal response_status, response_headers
        response_status = status
        response_headers = dict(headers)

    result = app(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "wsgi.input": BytesIO(),
        },
        start_response,
    )
    return response_status, response_headers, b"".join(result)


@pytest.mark.parametrize(
    ("path", "expected_text"),
    [
        ("/checkout/success", b"Payment submitted"),
        ("/checkout/cancel", b"Checkout canceled"),
    ],
)
def test_checkout_landing_pages_are_informational_only(
    tmp_path: Path,
    path: str,
    expected_text: bytes,
) -> None:
    service, gateway, _public = _service(tmp_path)

    status, headers, body = _wsgi_get(StripeLicensingWSGIApp(service), path)

    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert expected_text in body
    assert gateway.session_retrievals == 0


def test_paid_checkout_distributes_a_device_bound_signed_license(tmp_path: Path) -> None:
    service, gateway, public = _service(tmp_path)
    checkout = _checkout(service)

    assert checkout["checkout_url"].startswith("https://checkout.stripe.com/")
    assert checkout["activation_code"].startswith("MSAA-ACT-1.")
    assert gateway.created_params["mode"] == "subscription"
    assert gateway.created_params["line_items"] == [{"price": "price_msaa_monthly", "quantity": 1}]
    assert gateway.created_params["subscription_data"]["metadata"]["msaa_product_id"] == PRODUCT_ID
    with pytest.raises(StripeLicensingError) as pending:
        service.activate(
            {
                "product_id": PRODUCT_ID,
                "device_fingerprint": "1" * 64,
                "activation_code": checkout["activation_code"],
            }
        )
    assert pending.value.code == "LIC_PAYMENT_PENDING"

    _paid_session(service, gateway, checkout["order_id"])
    event_payload = _event(
        "evt_checkout_paid",
        "checkout.session.completed",
        {"id": "cs_test_msaa"},
    )
    result = service.handle_webhook(event_payload, "valid-test-signature")
    duplicate = service.handle_webhook(event_payload, "valid-test-signature")

    assert result["status"] == "processed"
    assert duplicate["status"] == "already_processed"
    assert gateway.session_retrievals == 2
    response = service.activate(
        {
            "product_id": PRODUCT_ID,
            "device_fingerprint": "1" * 64,
            "activation_code": checkout["activation_code"],
        }
    )
    document = response["license"]
    status = LicenseVerifier({"test-key": public}).verify(document, device_fingerprint="1" * 64)
    assert status.valid
    assert status.activation_mode == "stripe"
    assert status.licensed_to == "Example Buyer"
    assert "commercial_use" in status.features
    assert checkout["activation_code"].encode() not in service.config.database_path.read_bytes()
    assert service.config.activation_token_secret not in service.config.database_path.read_bytes()


def test_activation_reconciles_paid_checkout_when_webhook_is_delayed(tmp_path: Path) -> None:
    service, gateway, public = _service(tmp_path)
    checkout = _checkout(service)
    _paid_session(service, gateway, checkout["order_id"])

    response = service.activate(
        {
            "product_id": PRODUCT_ID,
            "device_fingerprint": "1" * 64,
            "activation_code": checkout["activation_code"],
        }
    )

    order = service.store.get_order(checkout["order_id"])
    status = LicenseVerifier({"test-key": public}).verify(
        response["license"],
        device_fingerprint="1" * 64,
    )
    assert order is not None and order.status == "ACTIVE"
    assert gateway.session_retrievals == 1
    assert status.valid
    assert status.activation_mode == "stripe"


def test_paid_invoice_extends_the_license_period(tmp_path: Path) -> None:
    service, gateway, _public = _service(tmp_path)
    checkout = _checkout(service)
    initial_end = _paid_session(service, gateway, checkout["order_id"])
    service.handle_webhook(
        _event("evt_initial", "checkout.session.completed", {"id": "cs_test_msaa"}),
        "valid-test-signature",
    )
    renewed_end = initial_end + 31 * 86_400
    invoice = {
        "id": "in_renewal",
        "status": "paid",
        "paid": True,
        "parent": {
            "subscription_details": {
                "subscription": "sub_test",
                "metadata": {
                    "msaa_order_id": checkout["order_id"],
                    "msaa_product_id": PRODUCT_ID,
                },
            }
        },
        "lines": {
            "data": [
                {
                    "pricing": {"price_details": {"price": "price_msaa_monthly"}},
                    "period": {"end": renewed_end},
                }
            ]
        },
    }

    service.handle_webhook(_event("evt_invoice_paid", "invoice.paid", invoice), "valid-test-signature")

    assert service.store.get_order(checkout["order_id"]).paid_until == renewed_end  # type: ignore[union-attr]
    document = service.activate(
        {
            "product_id": PRODUCT_ID,
            "device_fingerprint": "1" * 64,
            "activation_code": checkout["activation_code"],
        }
    )["license"]
    assert int(datetime.fromisoformat(document["expires_at"]).timestamp()) == renewed_end


def test_activation_code_cannot_move_to_another_installation(tmp_path: Path) -> None:
    service, gateway, _public = _service(tmp_path)
    checkout = _checkout(service)
    _paid_session(service, gateway, checkout["order_id"])
    service.handle_webhook(
        _event("evt_paid", "checkout.session.completed", {"id": "cs_test_msaa"}),
        "valid-test-signature",
    )

    with pytest.raises(StripeLicensingError) as mismatch:
        service.activate(
            {
                "product_id": PRODUCT_ID,
                "device_fingerprint": "2" * 64,
                "activation_code": checkout["activation_code"],
            }
        )

    assert mismatch.value.code == "LIC_DEVICE_MISMATCH"


def test_wrong_price_never_fulfills_or_consumes_the_webhook(tmp_path: Path) -> None:
    service, gateway, _public = _service(tmp_path)
    checkout = _checkout(service)
    _paid_session(service, gateway, checkout["order_id"])
    gateway.session["line_items"] = {"data": [{"price": {"id": "price_other"}}]}
    payload = _event("evt_wrong_price", "checkout.session.completed", {"id": "cs_test_msaa"})

    with pytest.raises(StripeLicensingError) as mismatch:
        service.handle_webhook(payload, "valid-test-signature")

    assert mismatch.value.code == "STRIPE_PRICE_MISMATCH"
    assert not service.store.event_processed("evt_wrong_price")


def test_unrelated_stripe_checkout_is_acknowledged_and_ignored(tmp_path: Path) -> None:
    service, gateway, _public = _service(tmp_path)
    gateway.session = {
        "id": "cs_test_other_product",
        "livemode": False,
        "payment_status": "paid",
        "client_reference_id": "not-an-msaa-order",
        "metadata": {"product": "other"},
        "line_items": {"data": [{"price": {"id": "price_other"}}]},
    }

    result = service.handle_webhook(
        _event("evt_other", "checkout.session.completed", {"id": "cs_test_other_product"}),
        "valid-test-signature",
    )

    assert result["status"] == "ignored"
    assert service.store.event_processed("evt_other")


def test_one_time_payment_issues_the_configured_fixed_term(tmp_path: Path) -> None:
    service, gateway, _public = _service(tmp_path, checkout_mode="payment")
    checkout = _checkout(service)
    _paid_session(service, gateway, checkout["order_id"])
    gateway.session["subscription"] = None

    before = datetime.now(timezone.utc)
    service.handle_webhook(
        _event("evt_one_time", "checkout.session.completed", {"id": "cs_test_msaa"}),
        "valid-test-signature",
    )
    document = service.activate(
        {
            "product_id": PRODUCT_ID,
            "device_fingerprint": "1" * 64,
            "activation_code": checkout["activation_code"],
        }
    )["license"]

    assert gateway.created_params["mode"] == "payment"
    assert gateway.created_params["customer_creation"] == "always"
    assert "payment_intent_data" in gateway.created_params
    expiry = datetime.fromisoformat(document["expires_at"])
    assert before + timedelta(days=364, hours=23) < expiry < before + timedelta(days=365, minutes=1)


def test_environment_loader_rejects_example_secrets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    values = {
        "STRIPE_SECRET_KEY": "sk_test_replace_me",
        "STRIPE_WEBHOOK_SECRET": "whsec_replace_me",
        "STRIPE_PRICE_ID": "price_replace_me",
        "MSAA_STRIPE_SUCCESS_URL": "https://licenses.example.test/success",
        "MSAA_STRIPE_CANCEL_URL": "https://licenses.example.test/cancel",
        "MSAA_STRIPE_DATABASE": str(tmp_path / "orders.sqlite3"),
        "MSAA_LICENSE_PRIVATE_KEY": str(tmp_path / "issuer.pem"),
        "MSAA_LICENSE_SIGNING_KEY_ID": "test-key",
        "MSAA_ACTIVATION_TOKEN_SECRET": "replace_with_at_least_32_random_bytes",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(StripeLicensingError) as rejected:
        StripeLicensingConfig.from_env()

    assert rejected.value.code == "STRIPE_CONFIG_PLACEHOLDER"
