from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .policy import DEFAULT_POLICY, LicensingPolicy
from .verifier import canonical_json


class ActivationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _service_http_error(exc: urllib.error.HTTPError, maximum_bytes: int) -> ActivationError:
    default = ActivationError("LIC_ACTIVATION_HTTP_ERROR", f"Activation service returned HTTP {exc.code}")
    try:
        data = exc.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            return default
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, Mapping):
            return default
        code = str(value.get("error_code", "")).strip()
        message = str(value.get("message", "")).strip()
        if (
            not code.startswith(("LIC_", "STRIPE_"))
            or len(code) > 128
            or not message
            or len(message) > 512
            or any(ord(char) < 32 for char in code + message)
        ):
            return default
        return ActivationError(code, message)
    except (UnicodeDecodeError, ValueError, OSError):
        return default


def _validate_activation_url(
    url: str,
    *,
    allow_private_hosts: bool,
    allow_fragment: bool = False,
) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or (parsed.fragment and not allow_fragment)
    ):
        raise ActivationError("LIC_ACTIVATION_URL_REJECTED", "Activation endpoint must be an HTTPS URL without embedded credentials")
    if parsed.port not in (None, 443):
        raise ActivationError("LIC_ACTIVATION_URL_REJECTED", "Activation endpoint must use the standard HTTPS port")
    if not allow_private_hosts:
        if parsed.hostname.lower() == "localhost" or parsed.hostname.lower().endswith(".local"):
            raise ActivationError("LIC_ACTIVATION_HOST_REJECTED", "Private activation hosts are disabled")
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ActivationError("LIC_ACTIVATION_DNS_FAILED", "Activation host could not be resolved") from exc
        for address in addresses:
            candidate = ipaddress.ip_address(address.split("%", 1)[0])
            if candidate.is_private or candidate.is_loopback or candidate.is_link_local or candidate.is_reserved or candidate.is_unspecified:
                raise ActivationError("LIC_ACTIVATION_HOST_REJECTED", "Activation host resolved to a non-public address")
    return parsed


class _RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, original_host: str, maximum_redirects: int = 3) -> None:
        super().__init__()
        self.original_host = original_host.lower()
        self.maximum_redirects = maximum_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        count = int(req.headers.get("X-MSAA-Redirect-Count", "0")) + 1
        parsed = urllib.parse.urlparse(newurl)
        if count > self.maximum_redirects or parsed.scheme != "https" or (parsed.hostname or "").lower() != self.original_host:
            raise ActivationError("LIC_ACTIVATION_REDIRECT_REJECTED", "Activation redirect was rejected")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.add_header("X-MSAA-Redirect-Count", str(count))
        return redirected


@dataclass(frozen=True)
class ActivationClient:
    endpoint: str
    policy: LicensingPolicy = DEFAULT_POLICY

    def activate(self, activation_code: str, request_payload: Mapping[str, Any]) -> dict[str, Any]:
        code = activation_code.strip()
        if not code or len(code) > 512 or any(ord(char) < 32 for char in code):
            raise ActivationError("LIC_ACTIVATION_CODE_INVALID", "Activation code is invalid")
        parsed = _validate_activation_url(self.endpoint, allow_private_hosts=self.policy.allow_private_activation_hosts)
        payload = dict(request_payload)
        payload["activation_code"] = code
        body = canonical_json(payload)
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "MSAA-License-Client/1"},
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
                declared = response.headers.get("Content-Length")
                if declared:
                    try:
                        declared_size = int(declared)
                    except ValueError as exc:
                        raise ActivationError("LIC_ACTIVATION_RESPONSE_INVALID", "Activation response contained an invalid length") from exc
                    if declared_size < 0 or declared_size > self.policy.maximum_activation_response_bytes:
                        raise ActivationError("LIC_ACTIVATION_RESPONSE_TOO_LARGE", "Activation response exceeded the size limit")
                data = response.read(self.policy.maximum_activation_response_bytes + 1)
        except ActivationError:
            raise
        except urllib.error.HTTPError as exc:
            raise _service_http_error(exc, self.policy.maximum_activation_response_bytes) from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise ActivationError("LIC_ACTIVATION_NETWORK_ERROR", "Secure activation request failed") from exc
        if len(data) > self.policy.maximum_activation_response_bytes:
            raise ActivationError("LIC_ACTIVATION_RESPONSE_TOO_LARGE", "Activation response exceeded the size limit")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ActivationError("LIC_ACTIVATION_RESPONSE_INVALID", "Activation response was not valid JSON") from exc
        if not isinstance(value, dict) or not isinstance(value.get("license"), dict):
            raise ActivationError("LIC_ACTIVATION_RESPONSE_INVALID", "Activation response did not contain a signed license")
        return dict(value["license"])
