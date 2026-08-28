from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .diff_engine import canonical_json
from .models import AuthorizationStatus, ProcessIdentity


@dataclass(frozen=True)
class AuthorizedChangeWindow:
    authorization_id: str
    requested_by: str
    approved_by: str | None
    reason: str
    ticket_reference: str | None
    allowed_control_ids: tuple[str, ...]
    allowed_executable_digests: tuple[str, ...]
    allowed_signing_identifiers: tuple[str, ...]
    starts_at_utc: datetime
    expires_at_utc: datetime
    created_at_utc: datetime
    signature: str

    def unsigned_payload(self) -> dict[str, object]:
        payload = asdict(self); payload.pop("signature", None); return payload


def sign_window(window: AuthorizedChangeWindow, key: bytes) -> str:
    return hmac.new(key, canonical_json(window.unsigned_payload()), hashlib.sha256).hexdigest()


def evaluate_authorization(window: AuthorizedChangeWindow | None, *, control_id: str, process: ProcessIdentity | None, verification_key: bytes | None, now: datetime | None = None) -> AuthorizationStatus:
    if window is None:
        return AuthorizationStatus.UNAUTHORIZED
    current = now or datetime.now(timezone.utc)
    if current < window.starts_at_utc or current > window.expires_at_utc:
        return AuthorizationStatus.EXPIRED
    if not window.allowed_control_ids or "*" in window.allowed_control_ids or control_id not in window.allowed_control_ids:
        return AuthorizationStatus.SCOPE_MISMATCH
    if verification_key is None or not hmac.compare_digest(window.signature, sign_window(window, verification_key)):
        return AuthorizationStatus.SIGNATURE_INVALID
    if window.allowed_executable_digests or window.allowed_signing_identifiers:
        if process is None:
            return AuthorizationStatus.SCOPE_MISMATCH
        digest_ok = process.executable_sha256 in window.allowed_executable_digests
        signing_ok = process.signing_identifier in window.allowed_signing_identifiers
        if not (digest_ok or signing_ok):
            return AuthorizationStatus.SCOPE_MISMATCH
    return AuthorizationStatus.AUTHORIZED
