from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import uuid4
from wsgiref.simple_server import make_server

from .issuer import LicenseIssuanceError, LicenseIssuer
from .policy import PRODUCT_ID
from .verifier import canonical_json


class StripeLicensingError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> int:
    return int(value.astimezone(timezone.utc).timestamp())


def _plain(value: Any) -> Any:
    if hasattr(value, "to_dict_recursive"):
        return _plain(value.to_dict_recursive())
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _clean_text(value: Any, field_name: str, maximum: int, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise StripeLicensingError("STRIPE_REQUEST_INVALID", f"{field_name} must be text")
    cleaned = value.strip()
    if required and not cleaned:
        raise StripeLicensingError("STRIPE_REQUEST_INVALID", f"{field_name} is required")
    if len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise StripeLicensingError("STRIPE_REQUEST_INVALID", f"{field_name} is invalid")
    return cleaned


def _device_fingerprint(value: Any) -> str:
    fingerprint = _clean_text(value, "device_fingerprint", 64, required=True)
    if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
        raise StripeLicensingError(
            "STRIPE_DEVICE_INVALID",
            "device_fingerprint must be 64 lowercase hexadecimal characters",
        )
    return fingerprint


def _validated_https_url(
    value: str,
    field_name: str,
    *,
    allow_localhost: bool = False,
    allow_fragment: bool = False,
) -> str:
    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower()
    local_development = allow_localhost and hostname in {"127.0.0.1", "::1", "localhost"}
    reserved_example = hostname in {"example.com", "example.net", "example.org"} or hostname.endswith(
        (".example.com", ".example.net", ".example.org", ".example", ".invalid", ".test")
    )
    if (
        (parsed.scheme != "https" and not (local_development and parsed.scheme == "http"))
        or not hostname
        or reserved_example
        or parsed.username
        or parsed.password
        or (parsed.fragment and not allow_fragment)
    ):
        raise StripeLicensingError(
            "STRIPE_CONFIG_INVALID",
            f"{field_name} must be a non-placeholder HTTPS URL without embedded credentials or a fragment",
            http_status=500,
        )
    return value


@dataclass(frozen=True)
class StripeLicensingConfig:
    stripe_secret_key: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    price_id: str
    success_url: str
    cancel_url: str
    database_path: Path
    private_key_path: Path
    signing_key_id: str
    activation_token_secret: bytes = field(repr=False)
    private_key_password: str | None = field(default=None, repr=False)
    checkout_mode: str = "subscription"
    one_time_license_days: int = 365
    edition: str = "COMMERCIAL"
    features: tuple[str, ...] = ("commercial_use", "professional_reports")
    expected_livemode: bool = False
    automatic_tax: bool = False

    @classmethod
    def from_env(cls) -> StripeLicensingConfig:
        required = {
            "stripe_secret_key": "STRIPE_SECRET_KEY",
            "webhook_secret": "STRIPE_WEBHOOK_SECRET",
            "price_id": "STRIPE_PRICE_ID",
            "success_url": "MSAA_STRIPE_SUCCESS_URL",
            "cancel_url": "MSAA_STRIPE_CANCEL_URL",
            "database_path": "MSAA_STRIPE_DATABASE",
            "private_key_path": "MSAA_LICENSE_PRIVATE_KEY",
            "signing_key_id": "MSAA_LICENSE_SIGNING_KEY_ID",
            "activation_token_secret": "MSAA_ACTIVATION_TOKEN_SECRET",
        }
        values: dict[str, str] = {}
        missing: list[str] = []
        for destination, environment_name in required.items():
            value = os.environ.get(environment_name, "").strip()
            if not value:
                missing.append(environment_name)
            values[destination] = value
        if missing:
            raise StripeLicensingError(
                "STRIPE_CONFIG_MISSING",
                "Missing required configuration: " + ", ".join(sorted(missing)),
                http_status=500,
            )
        placeholder_names = [
            environment_name
            for destination, environment_name in required.items()
            if any(marker in values[destination].lower() for marker in ("replace_me", "replace_with", "placeholder"))
        ]
        if placeholder_names:
            raise StripeLicensingError(
                "STRIPE_CONFIG_PLACEHOLDER",
                "Replace example values before startup: " + ", ".join(sorted(placeholder_names)),
                http_status=500,
            )
        mode = os.environ.get("MSAA_STRIPE_CHECKOUT_MODE", "subscription").strip().lower()
        if mode not in {"payment", "subscription"}:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_STRIPE_CHECKOUT_MODE must be payment or subscription",
                http_status=500,
            )
        try:
            license_days = int(os.environ.get("MSAA_STRIPE_ONE_TIME_LICENSE_DAYS", "365"))
        except ValueError as exc:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_STRIPE_ONE_TIME_LICENSE_DAYS must be an integer",
                http_status=500,
            ) from exc
        if license_days < 1 or license_days > 3660:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_STRIPE_ONE_TIME_LICENSE_DAYS must be between 1 and 3660",
                http_status=500,
            )
        token_secret = values["activation_token_secret"].encode("utf-8")
        if len(token_secret) < 32:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_ACTIVATION_TOKEN_SECRET must contain at least 32 bytes",
                http_status=500,
            )
        allow_localhost = os.environ.get("MSAA_STRIPE_ALLOW_INSECURE_LOCALHOST", "").strip() == "1"
        features = tuple(
            sorted(
                {
                    item.strip().lower()
                    for item in os.environ.get(
                        "MSAA_STRIPE_LICENSE_FEATURES",
                        "commercial_use,professional_reports",
                    ).split(",")
                    if item.strip()
                }
            )
        )
        expected_livemode = os.environ.get("MSAA_STRIPE_LIVE_MODE", "").strip() == "1"
        secret_key = values["stripe_secret_key"]
        expected_key_marker = "_live_" if expected_livemode else "_test_"
        if not secret_key.startswith(("sk_", "rk_")) or expected_key_marker not in secret_key:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "STRIPE_SECRET_KEY does not match MSAA_STRIPE_LIVE_MODE",
                http_status=500,
            )
        if not values["webhook_secret"].startswith("whsec_"):
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "STRIPE_WEBHOOK_SECRET must be an endpoint signing secret",
                http_status=500,
            )
        if not values["price_id"].startswith("price_"):
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "STRIPE_PRICE_ID must be a Stripe Price identifier",
                http_status=500,
            )
        database_path = Path(values["database_path"]).expanduser()
        private_key_path = Path(values["private_key_path"]).expanduser()
        if not database_path.is_absolute() or not private_key_path.is_absolute():
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_STRIPE_DATABASE and MSAA_LICENSE_PRIVATE_KEY must be absolute paths",
                http_status=500,
            )
        if not features:
            raise StripeLicensingError(
                "STRIPE_CONFIG_INVALID",
                "MSAA_STRIPE_LICENSE_FEATURES must grant at least one feature",
                http_status=500,
            )
        return cls(
            stripe_secret_key=secret_key,
            webhook_secret=values["webhook_secret"],
            price_id=values["price_id"],
            success_url=_validated_https_url(values["success_url"], "MSAA_STRIPE_SUCCESS_URL", allow_localhost=allow_localhost),
            cancel_url=_validated_https_url(values["cancel_url"], "MSAA_STRIPE_CANCEL_URL", allow_localhost=allow_localhost),
            database_path=database_path,
            private_key_path=private_key_path,
            signing_key_id=values["signing_key_id"],
            activation_token_secret=token_secret,
            private_key_password=os.environ.get("MSAA_LICENSE_PRIVATE_KEY_PASSWORD") or None,
            checkout_mode=mode,
            one_time_license_days=license_days,
            edition=os.environ.get("MSAA_STRIPE_LICENSE_EDITION", "COMMERCIAL").strip().upper(),
            features=features,
            expected_livemode=expected_livemode,
            automatic_tax=os.environ.get("MSAA_STRIPE_AUTOMATIC_TAX", "").strip() == "1",
        )


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    product_id: str
    device_fingerprint: str
    status: str
    checkout_session_id: str
    stripe_customer_id: str
    stripe_subscription_id: str
    licensed_to: str
    customer_email: str
    paid_until: int | None


class StripeGateway(Protocol):
    def create_checkout_session(self, params: dict[str, Any], *, idempotency_key: str) -> dict[str, Any]: ...

    def retrieve_checkout_session(self, session_id: str) -> dict[str, Any]: ...

    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]: ...

    def construct_webhook_event(self, payload: bytes, signature: str, secret: str) -> dict[str, Any]: ...


class StripeSDKGateway:
    """Small adapter around stripe-python so the fulfillment core stays testable."""

    def __init__(self, api_key: str) -> None:
        try:
            import stripe
        except ImportError as exc:
            raise StripeLicensingError(
                "STRIPE_SDK_UNAVAILABLE",
                "Install the licensing-server extra to run the Stripe service",
                http_status=500,
            ) from exc
        self._stripe = stripe
        self._client = stripe.StripeClient(api_key)

    def create_checkout_session(self, params: dict[str, Any], *, idempotency_key: str) -> dict[str, Any]:
        value = self._client.v1.checkout.sessions.create(
            params=params,
            options={"idempotency_key": idempotency_key},
        )
        return dict(_plain(value))

    def retrieve_checkout_session(self, session_id: str) -> dict[str, Any]:
        value = self._client.v1.checkout.sessions.retrieve(
            session_id,
            params={"expand": ["line_items"]},
        )
        return dict(_plain(value))

    def retrieve_subscription(self, subscription_id: str) -> dict[str, Any]:
        value = self._client.v1.subscriptions.retrieve(subscription_id)
        return dict(_plain(value))

    def construct_webhook_event(self, payload: bytes, signature: str, secret: str) -> dict[str, Any]:
        return dict(_plain(self._stripe.Webhook.construct_event(payload, signature, secret)))


class ActivationTokenCodec:
    prefix = "MSAA-ACT-1"

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("Activation token secret must contain at least 32 bytes")
        self._secret = secret

    def encode(self, order_id: str) -> str:
        digest = hmac.new(self._secret, order_id.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{self.prefix}.{order_id}.{digest}"

    def decode(self, activation_code: str) -> str:
        code = str(activation_code).strip()
        parts = code.split(".")
        if len(parts) != 3 or parts[0] != self.prefix:
            raise StripeLicensingError("LIC_ACTIVATION_CODE_INVALID", "Activation code is invalid", http_status=403)
        order_id, supplied = parts[1], parts[2]
        if len(order_id) != 32 or any(char not in "0123456789abcdef" for char in order_id):
            raise StripeLicensingError("LIC_ACTIVATION_CODE_INVALID", "Activation code is invalid", http_status=403)
        expected = hmac.new(self._secret, order_id.encode("ascii"), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(supplied, expected):
            raise StripeLicensingError("LIC_ACTIVATION_CODE_INVALID", "Activation code is invalid", http_status=403)
        return order_id


class OrderStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS license_orders (
                    order_id TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL,
                    device_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    checkout_session_id TEXT UNIQUE,
                    stripe_customer_id TEXT,
                    stripe_subscription_id TEXT UNIQUE,
                    licensed_to TEXT NOT NULL DEFAULT '',
                    customer_email TEXT NOT NULL DEFAULT '',
                    paid_until INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS processed_stripe_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    processed_at INTEGER NOT NULL
                );
                """
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _record(row: sqlite3.Row | None) -> OrderRecord | None:
        if row is None:
            return None
        return OrderRecord(
            order_id=str(row["order_id"]),
            product_id=str(row["product_id"]),
            device_fingerprint=str(row["device_fingerprint"]),
            status=str(row["status"]),
            checkout_session_id=str(row["checkout_session_id"] or ""),
            stripe_customer_id=str(row["stripe_customer_id"] or ""),
            stripe_subscription_id=str(row["stripe_subscription_id"] or ""),
            licensed_to=str(row["licensed_to"] or ""),
            customer_email=str(row["customer_email"] or ""),
            paid_until=int(row["paid_until"]) if row["paid_until"] is not None else None,
        )

    def create_order(self, order_id: str, product_id: str, device_fingerprint: str, *, licensed_to: str, email: str) -> None:
        now = _timestamp(_utc_now())
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO license_orders (
                    order_id, product_id, device_fingerprint, status,
                    licensed_to, customer_email, created_at, updated_at
                ) VALUES (?, ?, ?, 'PENDING', ?, ?, ?, ?)
                """,
                (order_id, product_id, device_fingerprint, licensed_to, email, now, now),
            )

    def attach_checkout_session(self, order_id: str, session_id: str) -> None:
        with self._transaction() as connection:
            cursor = connection.execute(
                "UPDATE license_orders SET checkout_session_id = ?, updated_at = ? WHERE order_id = ?",
                (session_id, _timestamp(_utc_now()), order_id),
            )
            if cursor.rowcount != 1:
                raise StripeLicensingError("STRIPE_ORDER_UNKNOWN", "Checkout order was not found", http_status=404)

    def get_order(self, order_id: str) -> OrderRecord | None:
        with self._connect() as connection:
            return self._record(connection.execute("SELECT * FROM license_orders WHERE order_id = ?", (order_id,)).fetchone())

    def get_order_by_subscription(self, subscription_id: str) -> OrderRecord | None:
        with self._connect() as connection:
            return self._record(
                connection.execute(
                    "SELECT * FROM license_orders WHERE stripe_subscription_id = ?",
                    (subscription_id,),
                ).fetchone()
            )

    def fulfill(
        self,
        order_id: str,
        *,
        session_id: str | None = None,
        customer_id: str = "",
        subscription_id: str = "",
        licensed_to: str = "",
        email: str = "",
        paid_until: int,
    ) -> OrderRecord:
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM license_orders WHERE order_id = ?", (order_id,)).fetchone()
            current = self._record(row)
            if current is None:
                raise StripeLicensingError("STRIPE_ORDER_UNKNOWN", "Checkout order was not found", http_status=404)
            if session_id and current.checkout_session_id and not secrets.compare_digest(current.checkout_session_id, session_id):
                raise StripeLicensingError("STRIPE_SESSION_MISMATCH", "Checkout Session does not match the order", http_status=409)
            effective_until = max(current.paid_until or 0, int(paid_until))
            connection.execute(
                """
                UPDATE license_orders
                SET status = 'ACTIVE',
                    checkout_session_id = COALESCE(NULLIF(?, ''), checkout_session_id),
                    stripe_customer_id = COALESCE(NULLIF(?, ''), stripe_customer_id),
                    stripe_subscription_id = COALESCE(NULLIF(?, ''), stripe_subscription_id),
                    licensed_to = COALESCE(NULLIF(?, ''), licensed_to),
                    customer_email = COALESCE(NULLIF(?, ''), customer_email),
                    paid_until = ?, updated_at = ?
                WHERE order_id = ?
                """,
                (
                    session_id or "",
                    customer_id,
                    subscription_id,
                    licensed_to,
                    email,
                    effective_until,
                    _timestamp(_utc_now()),
                    order_id,
                ),
            )
        result = self.get_order(order_id)
        if result is None:
            raise StripeLicensingError("STRIPE_ORDER_UNKNOWN", "Checkout order was not found", http_status=404)
        return result

    def set_subscription_status(self, subscription_id: str, status: str) -> bool:
        with self._transaction() as connection:
            cursor = connection.execute(
                "UPDATE license_orders SET status = ?, updated_at = ? WHERE stripe_subscription_id = ?",
                (status, _timestamp(_utc_now()), subscription_id),
            )
            return cursor.rowcount > 0

    def event_processed(self, event_id: str) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM processed_stripe_events WHERE event_id = ?",
                (event_id,),
            ).fetchone() is not None

    def record_event(self, event_id: str, event_type: str) -> None:
        with self._transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO processed_stripe_events (event_id, event_type, processed_at) VALUES (?, ?, ?)",
                (event_id, event_type, _timestamp(_utc_now())),
            )

    def health(self) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok", "database": "reachable"}


def _line_price_id(line: Mapping[str, Any]) -> str:
    price = line.get("price")
    if isinstance(price, Mapping):
        return str(price.get("id", ""))
    pricing = line.get("pricing")
    if isinstance(pricing, Mapping):
        details = pricing.get("price_details")
        if isinstance(details, Mapping):
            nested = details.get("price")
            if isinstance(nested, Mapping):
                return str(nested.get("id", ""))
            return str(nested or "")
    return ""


def _line_items(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    lines = value.get("line_items") or value.get("lines") or {}
    if not isinstance(lines, Mapping):
        return []
    data = lines.get("data", [])
    return [item for item in data if isinstance(item, Mapping)] if isinstance(data, list) else []


def _metadata(value: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = value.get("metadata")
    return metadata if isinstance(metadata, Mapping) else {}


def _invoice_subscription_id(invoice: Mapping[str, Any]) -> str:
    direct = invoice.get("subscription")
    if isinstance(direct, Mapping):
        direct = direct.get("id")
    if direct:
        return str(direct)
    parent = invoice.get("parent")
    if isinstance(parent, Mapping):
        details = parent.get("subscription_details")
        if isinstance(details, Mapping):
            subscription = details.get("subscription")
            if isinstance(subscription, Mapping):
                subscription = subscription.get("id")
            return str(subscription or "")
    return ""


def _invoice_metadata(invoice: Mapping[str, Any]) -> Mapping[str, Any]:
    parent = invoice.get("parent")
    if isinstance(parent, Mapping):
        details = parent.get("subscription_details")
        if isinstance(details, Mapping) and isinstance(details.get("metadata"), Mapping):
            return details["metadata"]
    details = invoice.get("subscription_details")
    if isinstance(details, Mapping) and isinstance(details.get("metadata"), Mapping):
        return details["metadata"]
    return _metadata(invoice)


class StripeLicensingService:
    def __init__(
        self,
        config: StripeLicensingConfig,
        *,
        gateway: StripeGateway | None = None,
        store: OrderStore | None = None,
        issuer: LicenseIssuer | None = None,
    ) -> None:
        self.config = config
        self.gateway = gateway or StripeSDKGateway(config.stripe_secret_key)
        self.store = store or OrderStore(config.database_path)
        self.issuer = issuer or LicenseIssuer.from_pem(
            config.private_key_path,
            key_id=config.signing_key_id,
            password=config.private_key_password,
        )
        self.tokens = ActivationTokenCodec(config.activation_token_secret)

    def create_checkout(self, request: Mapping[str, Any]) -> dict[str, Any]:
        product_id = _clean_text(request.get("product_id"), "product_id", 256, required=True)
        if product_id != PRODUCT_ID:
            raise StripeLicensingError("STRIPE_PRODUCT_MISMATCH", "Checkout requested an unsupported product")
        fingerprint = _device_fingerprint(request.get("device_fingerprint"))
        email = _clean_text(request.get("customer_email", ""), "customer_email", 254)
        if email and ("@" not in email or email.startswith("@") or email.endswith("@")):
            raise StripeLicensingError("STRIPE_REQUEST_INVALID", "customer_email is invalid")
        licensed_to = _clean_text(request.get("licensed_to", ""), "licensed_to", 256)
        request_nonce = _clean_text(request.get("request_nonce"), "request_nonce", 128, required=True)
        if len(request_nonce) < 16:
            raise StripeLicensingError("STRIPE_REQUEST_INVALID", "request_nonce is too short")
        order_id = uuid4().hex
        self.store.create_order(order_id, product_id, fingerprint, licensed_to=licensed_to, email=email)
        metadata = {"msaa_order_id": order_id, "msaa_product_id": product_id}
        params: dict[str, Any] = {
            "mode": self.config.checkout_mode,
            "line_items": [{"price": self.config.price_id, "quantity": 1}],
            "success_url": self.config.success_url,
            "cancel_url": self.config.cancel_url,
            "client_reference_id": order_id,
            "metadata": metadata,
            "automatic_tax": {"enabled": self.config.automatic_tax},
        }
        if email:
            params["customer_email"] = email
        if self.config.checkout_mode == "subscription":
            params["subscription_data"] = {"metadata": metadata}
        else:
            params["customer_creation"] = "always"
            params["payment_intent_data"] = {"metadata": metadata}
        try:
            session = self.gateway.create_checkout_session(
                params,
                idempotency_key=f"msaa-checkout-{order_id}-{hashlib.sha256(request_nonce.encode()).hexdigest()[:16]}",
            )
        except StripeLicensingError:
            raise
        except Exception as exc:
            raise StripeLicensingError(
                "STRIPE_CHECKOUT_FAILED",
                "Stripe Checkout could not be created",
                http_status=502,
            ) from exc
        session_id = _clean_text(session.get("id"), "checkout_session.id", 255, required=True)
        checkout_url = _validated_https_url(
            _clean_text(session.get("url"), "checkout_session.url", 2048, required=True),
            "checkout_session.url",
            allow_fragment=True,
        )
        livemode = session.get("livemode")
        if livemode is not None and bool(livemode) != self.config.expected_livemode:
            raise StripeLicensingError(
                "STRIPE_MODE_MISMATCH",
                "Stripe Checkout mode does not match server configuration",
                http_status=502,
            )
        self.store.attach_checkout_session(order_id, session_id)
        return {
            "checkout_url": checkout_url,
            "activation_code": self.tokens.encode(order_id),
            "order_id": order_id,
            "status": "PENDING_PAYMENT",
        }

    def _subscription_paid_until(self, subscription_id: str) -> int:
        try:
            subscription = self.gateway.retrieve_subscription(subscription_id)
        except Exception as exc:
            raise StripeLicensingError(
                "STRIPE_SUBSCRIPTION_LOOKUP_FAILED",
                "Stripe subscription could not be verified",
                http_status=502,
            ) from exc
        if subscription.get("status") not in {"active", "trialing"}:
            raise StripeLicensingError(
                "STRIPE_SUBSCRIPTION_INACTIVE",
                "Stripe subscription is not active",
                http_status=409,
            )
        items = subscription.get("items", {})
        data = items.get("data", []) if isinstance(items, Mapping) else []
        periods = [
            int(item.get("current_period_end", 0))
            for item in data
            if isinstance(item, Mapping)
            and _line_price_id(item) == self.config.price_id
            and int(item.get("current_period_end", 0)) > 0
        ]
        if not periods:
            raise StripeLicensingError(
                "STRIPE_PRICE_MISMATCH",
                "Subscription does not contain the configured MSAA price",
                http_status=409,
            )
        return max(periods)

    def _fulfill_checkout_session(self, session_id: str) -> bool:
        try:
            session = self.gateway.retrieve_checkout_session(session_id)
        except Exception as exc:
            raise StripeLicensingError(
                "STRIPE_SESSION_LOOKUP_FAILED",
                "Stripe Checkout Session could not be verified",
                http_status=502,
            ) from exc
        if str(session.get("id", "")) != session_id:
            raise StripeLicensingError("STRIPE_SESSION_MISMATCH", "Stripe returned a different Checkout Session", http_status=409)
        if bool(session.get("livemode", False)) != self.config.expected_livemode:
            raise StripeLicensingError("STRIPE_MODE_MISMATCH", "Stripe event mode does not match server configuration", http_status=409)
        payment_status = str(session.get("payment_status", ""))
        if payment_status == "unpaid":
            return True
        if payment_status not in {"paid", "no_payment_required"}:
            raise StripeLicensingError("STRIPE_PAYMENT_STATUS_INVALID", "Stripe Session is not paid", http_status=409)
        metadata = _metadata(session)
        order_id = str(session.get("client_reference_id", "") or metadata.get("msaa_order_id", ""))
        order = self.store.get_order(order_id)
        if order is None:
            return False
        if metadata.get("msaa_product_id") != PRODUCT_ID or order.product_id != PRODUCT_ID:
            raise StripeLicensingError("STRIPE_PRODUCT_MISMATCH", "Stripe Session product metadata is invalid", http_status=409)
        if order.checkout_session_id != session_id:
            raise StripeLicensingError("STRIPE_SESSION_MISMATCH", "Stripe Session is not attached to its order", http_status=409)
        if not any(_line_price_id(line) == self.config.price_id for line in _line_items(session)):
            raise StripeLicensingError("STRIPE_PRICE_MISMATCH", "Stripe Session does not contain the configured MSAA price", http_status=409)
        subscription = session.get("subscription")
        if isinstance(subscription, Mapping):
            subscription = subscription.get("id")
        subscription_id = str(subscription or "")
        if self.config.checkout_mode == "subscription":
            if not subscription_id:
                raise StripeLicensingError("STRIPE_SUBSCRIPTION_MISSING", "Paid checkout omitted its subscription", http_status=409)
            paid_until = self._subscription_paid_until(subscription_id)
        else:
            paid_until = _timestamp(_utc_now() + timedelta(days=self.config.one_time_license_days))
        customer = session.get("customer")
        if isinstance(customer, Mapping):
            customer = customer.get("id")
        details = session.get("customer_details")
        details = details if isinstance(details, Mapping) else {}
        email = _clean_text(details.get("email", order.customer_email), "customer_details.email", 254)
        licensed_to = _clean_text(details.get("name", order.licensed_to), "customer_details.name", 256)
        self.store.fulfill(
            order_id,
            session_id=session_id,
            customer_id=str(customer or ""),
            subscription_id=subscription_id,
            licensed_to=licensed_to or email or "MSAA customer",
            email=email,
            paid_until=paid_until,
        )
        return True

    def _fulfill_invoice(self, invoice: Mapping[str, Any]) -> bool:
        if invoice.get("status") != "paid" and invoice.get("paid") is not True:
            raise StripeLicensingError("STRIPE_INVOICE_UNPAID", "Stripe invoice is not paid", http_status=409)
        subscription_id = _invoice_subscription_id(invoice)
        metadata = _invoice_metadata(invoice)
        order = self.store.get_order_by_subscription(subscription_id) if subscription_id else None
        if order is None and metadata.get("msaa_order_id"):
            order = self.store.get_order(str(metadata["msaa_order_id"]))
        if order is None:
            return False
        if metadata.get("msaa_product_id") not in {None, "", PRODUCT_ID}:
            raise StripeLicensingError("STRIPE_PRODUCT_MISMATCH", "Stripe invoice is not for MSAA", http_status=409)
        matching_lines = [line for line in _line_items(invoice) if _line_price_id(line) == self.config.price_id]
        if not matching_lines:
            raise StripeLicensingError("STRIPE_PRICE_MISMATCH", "Stripe invoice does not contain the configured MSAA price", http_status=409)
        periods = [
            int(period.get("end", 0))
            for line in matching_lines
            for period in [line.get("period", {})]
            if isinstance(period, Mapping) and int(period.get("end", 0)) > 0
        ]
        if not periods:
            raise StripeLicensingError("STRIPE_PERIOD_MISSING", "Paid invoice omitted its service period", http_status=409)
        self.store.fulfill(
            order.order_id,
            subscription_id=subscription_id,
            paid_until=max(periods),
        )
        return True

    def handle_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        if not signature:
            raise StripeLicensingError("STRIPE_SIGNATURE_MISSING", "Stripe-Signature header is required")
        try:
            event = self.gateway.construct_webhook_event(payload, signature, self.config.webhook_secret)
        except Exception as exc:
            raise StripeLicensingError("STRIPE_SIGNATURE_INVALID", "Stripe webhook signature verification failed") from exc
        event_id = _clean_text(event.get("id"), "event.id", 255, required=True)
        event_type = _clean_text(event.get("type"), "event.type", 128, required=True)
        if bool(event.get("livemode", False)) != self.config.expected_livemode:
            raise StripeLicensingError("STRIPE_MODE_MISMATCH", "Stripe event mode does not match server configuration", http_status=409)
        if self.store.event_processed(event_id):
            return {"status": "already_processed", "event_id": event_id}
        data = event.get("data")
        event_object = data.get("object") if isinstance(data, Mapping) else None
        if not isinstance(event_object, Mapping):
            raise StripeLicensingError("STRIPE_EVENT_INVALID", "Stripe event omitted its data object")
        handled = False
        if event_type in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
            handled = self._fulfill_checkout_session(
                _clean_text(event_object.get("id"), "session.id", 255, required=True)
            )
        elif event_type == "invoice.paid":
            handled = self._fulfill_invoice(event_object)
        elif event_type == "invoice.payment_failed":
            subscription_id = _invoice_subscription_id(event_object)
            if subscription_id:
                handled = self.store.set_subscription_status(subscription_id, "PAST_DUE")
        elif event_type == "customer.subscription.deleted":
            subscription_id = _clean_text(event_object.get("id"), "subscription.id", 255, required=True)
            handled = self.store.set_subscription_status(subscription_id, "ENDED")
        elif event_type == "checkout.session.async_payment_failed":
            session_id = _clean_text(event_object.get("id"), "session.id", 255, required=True)
            order_id = str(event_object.get("client_reference_id", "") or _metadata(event_object).get("msaa_order_id", ""))
            order = self.store.get_order(order_id)
            handled = bool(order and order.checkout_session_id == session_id)
        self.store.record_event(event_id, event_type)
        return {
            "status": "processed" if handled else "ignored",
            "event_id": event_id,
        }

    def activate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        product_id = _clean_text(request.get("product_id"), "product_id", 256, required=True)
        if product_id != PRODUCT_ID:
            raise StripeLicensingError("LIC_PRODUCT_MISMATCH", "Activation requested an unsupported product", http_status=403)
        fingerprint = _device_fingerprint(request.get("device_fingerprint"))
        activation_code = _clean_text(request.get("activation_code"), "activation_code", 512, required=True)
        order = self.store.get_order(self.tokens.decode(activation_code))
        if order is None:
            raise StripeLicensingError("LIC_ACTIVATION_CODE_INVALID", "Activation code is invalid", http_status=403)
        if not secrets.compare_digest(order.device_fingerprint, fingerprint):
            raise StripeLicensingError("LIC_DEVICE_MISMATCH", "Purchase is bound to a different MSAA installation", http_status=403)
        if (order.status == "PENDING" or order.paid_until is None) and order.checkout_session_id:
            # Webhooks remain the normal fulfillment path, but activation must
            # not strand a paid customer when Stripe delivery is delayed. The
            # same server-side verification used by the webhook checks the
            # exact attached Session, mode, product, price, and subscription
            # before changing the local order.
            self._fulfill_checkout_session(order.checkout_session_id)
            refreshed_order = self.store.get_order(order.order_id)
            if refreshed_order is not None:
                order = refreshed_order
        now = _utc_now()
        if order.status == "PENDING" or order.paid_until is None:
            raise StripeLicensingError("LIC_PAYMENT_PENDING", "Stripe payment has not been fulfilled yet", http_status=409)
        if order.paid_until <= _timestamp(now):
            raise StripeLicensingError("LIC_SUBSCRIPTION_INACTIVE", "The paid license period has ended", http_status=403)
        try:
            license_document = self.issuer.issue(
                license_id=f"MSAA-STRIPE-{order.order_id.upper()}",
                licensed_to=order.licensed_to or order.customer_email or "MSAA customer",
                device_fingerprint=order.device_fingerprint,
                expires_at=datetime.fromtimestamp(order.paid_until, timezone.utc),
                features=self.config.features,
                edition=self.config.edition,
                activation_mode="stripe",
                now=now,
            )
        except LicenseIssuanceError as exc:
            raise StripeLicensingError("LIC_ISSUANCE_FAILED", "The paid license could not be issued", http_status=500) from exc
        return {"license": license_document}


class StripeLicensingWSGIApp:
    maximum_request_bytes = 524_288

    def __init__(self, service: StripeLicensingService) -> None:
        self.service = service

    @staticmethod
    def _response(start_response, status: str, value: Mapping[str, Any]):  # type: ignore[no-untyped-def]
        body = canonical_json(dict(value)) + b"\n"
        start_response(
            status,
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        return [body]

    @staticmethod
    def _html_response(start_response, status: str, *, title: str, message: str):  # type: ignore[no-untyped-def]
        body = (
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{title}</title>"
            "<style>body{font:16px system-ui,sans-serif;max-width:42rem;margin:12vh auto;"
            "padding:0 1.25rem;color:#172033}h1{font-size:1.8rem}p{line-height:1.55}</style>"
            f"<main><h1>{title}</h1><p>{message}</p></main></html>"
        ).encode()
        start_response(
            status,
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"),
                ("Referrer-Policy", "no-referrer"),
            ],
        )
        return [body]

    def _read_body(self, environ: Mapping[str, Any]) -> bytes:
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError as exc:
            raise StripeLicensingError("REQUEST_LENGTH_INVALID", "Content-Length is invalid") from exc
        if length < 0 or length > self.maximum_request_bytes:
            raise StripeLicensingError("REQUEST_TOO_LARGE", "Request body exceeded the size limit", http_status=413)
        return environ["wsgi.input"].read(length)

    def __call__(self, environ, start_response):  # type: ignore[no-untyped-def]
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))
        try:
            if method == "GET" and path == "/healthz":
                return self._response(start_response, "200 OK", self.service.store.health())
            if method == "GET" and path == "/checkout/success":
                return self._html_response(
                    start_response,
                    "200 OK",
                    title="Payment submitted",
                    message=(
                        "Return to MSAA and select Activate Online. Some payment methods take a short time "
                        "to confirm, so retry activation if Stripe is still processing the payment."
                    ),
                )
            if method == "GET" and path == "/checkout/cancel":
                return self._html_response(
                    start_response,
                    "200 OK",
                    title="Checkout canceled",
                    message="No license was issued. You can return to MSAA and start checkout again at any time.",
                )
            if method != "POST":
                raise StripeLicensingError("ROUTE_NOT_FOUND", "Route not found", http_status=404)
            body = self._read_body(environ)
            if path == "/v1/webhooks/stripe":
                result = self.service.handle_webhook(body, str(environ.get("HTTP_STRIPE_SIGNATURE", "")))
            elif path in {"/v1/checkout", "/v1/activate"}:
                try:
                    request = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise StripeLicensingError("REQUEST_JSON_INVALID", "Request body is not valid JSON") from exc
                if not isinstance(request, Mapping):
                    raise StripeLicensingError("REQUEST_JSON_INVALID", "Request body must be a JSON object")
                result = self.service.create_checkout(request) if path == "/v1/checkout" else self.service.activate(request)
            else:
                raise StripeLicensingError("ROUTE_NOT_FOUND", "Route not found", http_status=404)
            return self._response(start_response, "200 OK", result)
        except StripeLicensingError as exc:
            status_text = {
                400: "400 Bad Request",
                403: "403 Forbidden",
                404: "404 Not Found",
                409: "409 Conflict",
                413: "413 Payload Too Large",
                500: "500 Internal Server Error",
                502: "502 Bad Gateway",
            }.get(exc.http_status, "400 Bad Request")
            return self._response(start_response, status_text, {"error_code": exc.code, "message": str(exc)})
        except Exception:  # noqa: BLE001 - keep internal exception details out of HTTP responses
            return self._response(
                start_response,
                "500 Internal Server Error",
                {"error_code": "LICENSING_SERVICE_ERROR", "message": "Licensing service request failed"},
            )


def create_app_from_env() -> StripeLicensingWSGIApp:
    config = StripeLicensingConfig.from_env()
    return StripeLicensingWSGIApp(StripeLicensingService(config))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MSAA Stripe Checkout and signed-license service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--allow-development-server-external",
        action="store_true",
        help="Allow the stdlib development server to bind outside loopback (not recommended).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.port < 1 or args.port > 65_535:
        raise SystemExit("--port must be between 1 and 65535")
    if args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_development_server_external:
        raise SystemExit("Refusing an external bind with the development server; deploy the WSGI factory behind HTTPS instead")
    try:
        app = create_app_from_env()
    except (StripeLicensingError, LicenseIssuanceError, OSError, ValueError) as exc:
        print(f"Configuration rejected: {exc}", file=sys.stderr)
        return 2
    print(f"MSAA Stripe licensing development server listening on {args.host}:{args.port}", file=sys.stderr)
    with make_server(args.host, args.port, app) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
