from __future__ import annotations

from mac_audit_agent.compat.enum import StrEnum


class IntegrityResultCode(StrEnum):
    VALID = "VALID"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    MANIFEST_UNSIGNED = "MANIFEST_UNSIGNED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PUBLIC_KEY_MISSING = "PUBLIC_KEY_MISSING"
    HASH_MISMATCH = "HASH_MISMATCH"
    FILE_MISSING = "FILE_MISSING"
    UNEXPECTED_FILE = "UNEXPECTED_FILE"
    UNSUPPORTED_BUNDLE_LAYOUT = "UNSUPPORTED_BUNDLE_LAYOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def result_code_for_validation(
    *,
    status: str,
    trust_state: str,
    modified_files: list[str] | None = None,
    missing_files: list[str] | None = None,
    extra_files: list[str] | None = None,
) -> str:
    if status == "verified":
        return IntegrityResultCode.VALID.value
    if missing_files:
        return IntegrityResultCode.FILE_MISSING.value
    if extra_files:
        return IntegrityResultCode.UNEXPECTED_FILE.value
    if modified_files:
        return IntegrityResultCode.HASH_MISMATCH.value
    if trust_state in {"manifest_missing", "missing_manifest"}:
        return IntegrityResultCode.MANIFEST_MISSING.value
    if trust_state in {"signature_missing", "manifest_signature_missing", "unsigned_manifest", "unsigned_source_checkout"}:
        return IntegrityResultCode.MANIFEST_UNSIGNED.value
    if trust_state in {"trusted_public_key_missing", "developer_machine_not_enrolled", "yubikey_required"}:
        return IntegrityResultCode.PUBLIC_KEY_MISSING.value
    if trust_state in {"manifest_path_divergence", "runtime_manifest_mismatch"}:
        return IntegrityResultCode.UNSUPPORTED_BUNDLE_LAYOUT.value
    if trust_state in {
        "signature_invalid",
        "manifest_signature_invalid",
        "manifest_modified_after_signing",
        "invalid_signature",
        "developer_machine_revoked",
        "machine_fingerprint_mismatch",
        "manifest_quorum_missing",
    }:
        return IntegrityResultCode.SIGNATURE_INVALID.value
    if trust_state in {"source_files_modified", "modified_unapproved", "release_artifact_mismatch"}:
        return IntegrityResultCode.HASH_MISMATCH.value
    return IntegrityResultCode.INTERNAL_ERROR.value


__all__ = ["IntegrityResultCode", "result_code_for_validation"]
