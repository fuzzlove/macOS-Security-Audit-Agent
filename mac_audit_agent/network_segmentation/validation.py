from __future__ import annotations

import hmac
import secrets
from uuid import uuid4


def make_nonce() -> bytes:
    return f"MSAA-EGRESS-TEST:{uuid4()}:{secrets.token_hex(16)}".encode("ascii")


def validate_echo(sent: bytes, received: bytes, maximum_bytes: int = 4096) -> bool:
    if len(sent) > maximum_bytes or len(received) > maximum_bytes:
        return False
    return hmac.compare_digest(sent, received)
