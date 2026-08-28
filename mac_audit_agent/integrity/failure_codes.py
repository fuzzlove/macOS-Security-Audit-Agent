from __future__ import annotations

from mac_audit_agent.compat.enum import StrEnum


class IntegrityFailureCode(StrEnum):
    POLICY_PATH_DIVERGENCE = "POLICY_PATH_DIVERGENCE"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    MANIFEST_MODIFIED_AFTER_SIGNING = "MANIFEST_MODIFIED_AFTER_SIGNING"
    SOURCE_FILE_MODIFIED = "SOURCE_FILE_MODIFIED"
    GENERATED_ARTIFACT_ONLY = "GENERATED_ARTIFACT_ONLY"
    LEGACY_MANIFEST_CONFLICT = "LEGACY_MANIFEST_CONFLICT"
    HEADLESS_GUI_IMPORT = "HEADLESS_GUI_IMPORT"
    PASS_WITH_FAILED_EVIDENCE = "PASS_WITH_FAILED_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    ARTIFACT_HYGIENE_FAIL = "ARTIFACT_HYGIENE_FAIL"
    UNKNOWN_UNCLASSIFIED_ERROR = "UNKNOWN_UNCLASSIFIED_ERROR"


def failure_code_for_trust_state(trust_state: str, *, modified: bool = False, missing: bool = False, extra: bool = False) -> str:
    if modified or missing or extra or trust_state in {"source_files_modified", "modified_unapproved"}:
        return IntegrityFailureCode.SOURCE_FILE_MODIFIED.value
    if trust_state in {"signature_missing", "manifest_signature_missing", "unsigned_manifest"}:
        return IntegrityFailureCode.SIGNATURE_MISSING.value
    if trust_state == "manifest_modified_after_signing":
        return IntegrityFailureCode.MANIFEST_MODIFIED_AFTER_SIGNING.value
    if trust_state in {"signature_invalid", "manifest_signature_invalid", "invalid_signature", "trusted_public_key_missing"}:
        return IntegrityFailureCode.SIGNATURE_INVALID.value
    if trust_state == "manifest_path_divergence":
        return IntegrityFailureCode.POLICY_PATH_DIVERGENCE.value
    if trust_state == "generated_artifact_out_of_scope":
        return IntegrityFailureCode.GENERATED_ARTIFACT_ONLY.value
    return IntegrityFailureCode.UNKNOWN_UNCLASSIFIED_ERROR.value


__all__ = ["IntegrityFailureCode", "failure_code_for_trust_state"]
