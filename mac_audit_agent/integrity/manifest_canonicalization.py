from __future__ import annotations

from typing import Any

from mac_audit_agent.integrity.canonical import CANONICALIZATION_VERSION, canonical_payload_bytes


RUNTIME_ONLY_FIELDS = {
    "verification_status",
    "last_verified_at",
    "transient_error",
    "signature_status",
}


def canonicalize_manifest_for_signing(manifest: dict[str, Any]) -> bytes:
    return canonical_payload_bytes(manifest)


__all__ = ["CANONICALIZATION_VERSION", "RUNTIME_ONLY_FIELDS", "canonicalize_manifest_for_signing"]
