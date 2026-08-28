from __future__ import annotations

import json
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .activation import (
    ActivationError,
    _RestrictedRedirectHandler,
    _service_http_error,
    _validate_activation_url,
)
from .policy import DEFAULT_POLICY, LicensingPolicy
from .verifier import canonical_json


@dataclass(frozen=True)
class CheckoutClient:
    endpoint: str
    policy: LicensingPolicy = DEFAULT_POLICY

    def begin(
        self,
        *,
        product_id: str,
        device_fingerprint: str,
        customer_email: str = "",
        licensed_to: str = "",
    ) -> dict[str, Any]:
        parsed = _validate_activation_url(
            self.endpoint,
            allow_private_hosts=self.policy.allow_private_activation_hosts,
        )
        payload = {
            "product_id": product_id,
            "device_fingerprint": device_fingerprint,
            "request_nonce": secrets.token_urlsafe(24),
            "client_time": datetime.now(timezone.utc).isoformat(),
        }
        if customer_email.strip():
            payload["customer_email"] = customer_email.strip()
        if licensed_to.strip():
            payload["licensed_to"] = licensed_to.strip()
        request = urllib.request.Request(
            self.endpoint,
            data=canonical_json(payload),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "MSAA-License-Client/1",
            },
            method="POST",
        )
        context = ssl.create_default_context()
        try:
            import certifi

            context.load_verify_locations(certifi.where())
        except ImportError:
            pass
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _RestrictedRedirectHandler(parsed.hostname or ""),
        )
        try:
            with opener.open(request, timeout=self.policy.activation_timeout_seconds) as response:
                data = response.read(self.policy.maximum_activation_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            parsed_error = _service_http_error(exc, self.policy.maximum_activation_response_bytes)
            if parsed_error.code == "LIC_ACTIVATION_HTTP_ERROR":
                parsed_error = ActivationError("LIC_CHECKOUT_HTTP_ERROR", f"Checkout service returned HTTP {exc.code}")
            raise parsed_error from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise ActivationError("LIC_CHECKOUT_NETWORK_ERROR", "Secure checkout request failed") from exc
        if len(data) > self.policy.maximum_activation_response_bytes:
            raise ActivationError("LIC_CHECKOUT_RESPONSE_TOO_LARGE", "Checkout response exceeded the size limit")
        try:
            result = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ActivationError("LIC_CHECKOUT_RESPONSE_INVALID", "Checkout response was not valid JSON") from exc
        if not isinstance(result, dict):
            raise ActivationError("LIC_CHECKOUT_RESPONSE_INVALID", "Checkout response must be a JSON object")
        checkout_url = str(result.get("checkout_url", "")).strip()
        activation_code = str(result.get("activation_code", "")).strip()
        if not checkout_url or not activation_code or len(activation_code) > 512:
            raise ActivationError("LIC_CHECKOUT_RESPONSE_INVALID", "Checkout response omitted its URL or activation code")
        _validate_activation_url(
            checkout_url,
            allow_private_hosts=self.policy.allow_private_activation_hosts,
            allow_fragment=True,
        )
        return {
            "checkout_url": checkout_url,
            "activation_code": activation_code,
            "message": "Complete Stripe Checkout, then activate with the returned code.",
            "checkout_host": parsed.hostname or "",
        }
