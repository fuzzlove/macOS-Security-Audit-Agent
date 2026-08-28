from __future__ import annotations

from enum import Enum
from typing import Any


class IntegrityTrustState(str, Enum):
    TRUSTED_SIGNED_RELEASE = "trusted_signed_release"
    TRUSTED_DEVELOPMENT_BASELINE = "trusted_development_baseline"
    TRUSTED_DUAL_YUBIKEY_SIGNED_MANIFEST = "trusted_dual_yubikey_signed_manifest"
    TRUSTED_CODEX_APPROVED_CHANGE = "trusted_codex_approved_change"
    MODIFIED_PENDING_REVIEW = "modified_pending_review"
    MODIFIED_UNAPPROVED = "modified_unapproved"
    STALE_MANIFEST = "stale_manifest"
    MISSING_MANIFEST = "missing_manifest"
    MANIFEST_MISSING = "manifest_missing"
    UNSIGNED_SOURCE_CHECKOUT = "unsigned_source_checkout"
    UNSIGNED_RELEASE_ARTIFACT = "unsigned_release_artifact"
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    MANIFEST_SIGNATURE_MISSING = "manifest_signature_missing"
    MANIFEST_SIGNATURE_INVALID = "manifest_signature_invalid"
    MANIFEST_QUORUM_MISSING = "manifest_quorum_missing"
    YUBIKEY_REQUIRED = "yubikey_required"
    CODEX_PROVENANCE_UNVERIFIED = "codex_provenance_unverified"
    RELEASE_ARTIFACT_MISMATCH = "release_artifact_mismatch"
    GENERATED_ARTIFACT_OUT_OF_SCOPE = "generated_artifact_out_of_scope"
    MANIFEST_PATH_DIVERGENCE = "manifest_path_divergence"
    NON_APPLICABLE_FOR_POLICY = "non_applicable_for_policy"
    INVALID_SIGNATURE = "invalid_signature"
    RUNTIME_MANIFEST_MISMATCH = "runtime_manifest_mismatch"
    RUNTIME_MUTABLE_CHANGE_ONLY = "runtime_mutable_change_only"
    VERIFICATION_ERROR = "verification_error"


SOURCE_DEV_UNSIGNED_MESSAGE = "Unsigned source checkout: expected in source development mode unless signing is configured."
RELEASE_UNSIGNED_MESSAGE = "Unsigned release artifact: release trust requires signing or an explicitly documented release exception."


def signature_context_message(source_type: str, signature_status: str) -> tuple[str, str]:
    mode = str(source_type or "source_tree")
    signature = str(signature_status or "unsigned")
    if signature == "signed":
        return "Signed and verified", "info"
    if signature == "invalid":
        return "Signature invalid", "critical"
    if mode == "source_tree":
        return SOURCE_DEV_UNSIGNED_MESSAGE, "info"
    if mode in {"pyinstaller_app", "pip_package", "pypi_wheel"}:
        return RELEASE_UNSIGNED_MESSAGE, "high"
    return "Runtime verified by install manifest when manifest and permissions match.", "info"


def trust_basis_for_state(state: str, *, source_type: str = "", signature_status: str = "") -> str:
    trust_state = str(state or "")
    return {
        IntegrityTrustState.TRUSTED_SIGNED_RELEASE.value: "Signed release",
        IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value: "Trusted development manifest",
        IntegrityTrustState.TRUSTED_DUAL_YUBIKEY_SIGNED_MANIFEST.value: "Dual YubiKey signed manifest",
        IntegrityTrustState.TRUSTED_CODEX_APPROVED_CHANGE.value: "Approved Codex change baseline",
        IntegrityTrustState.MODIFIED_PENDING_REVIEW.value: "Approved change pending review and rebaseline",
        IntegrityTrustState.MODIFIED_UNAPPROVED.value: "Unverified modified source",
        IntegrityTrustState.STALE_MANIFEST.value: "Stale manifest",
        IntegrityTrustState.MISSING_MANIFEST.value: "Missing manifest",
        IntegrityTrustState.MANIFEST_MISSING.value: "Missing manifest",
        IntegrityTrustState.UNSIGNED_SOURCE_CHECKOUT.value: "Unsigned source checkout",
        IntegrityTrustState.UNSIGNED_RELEASE_ARTIFACT.value: "Unsigned release artifact",
        IntegrityTrustState.SIGNATURE_MISSING.value: "Signature missing",
        IntegrityTrustState.SIGNATURE_INVALID.value: "Signature invalid",
        IntegrityTrustState.MANIFEST_SIGNATURE_MISSING.value: "Manifest signature missing",
        IntegrityTrustState.MANIFEST_SIGNATURE_INVALID.value: "Manifest signature invalid",
        IntegrityTrustState.MANIFEST_QUORUM_MISSING.value: "Manifest quorum missing",
        IntegrityTrustState.YUBIKEY_REQUIRED.value: "YubiKey required",
        IntegrityTrustState.CODEX_PROVENANCE_UNVERIFIED.value: "Codex provenance unverified",
        IntegrityTrustState.INVALID_SIGNATURE.value: "Invalid signature",
        IntegrityTrustState.RELEASE_ARTIFACT_MISMATCH.value: "Release artifact mismatch",
        IntegrityTrustState.GENERATED_ARTIFACT_OUT_OF_SCOPE.value: "Generated artifacts out of scope",
        IntegrityTrustState.MANIFEST_PATH_DIVERGENCE.value: "Manifest path divergence",
        IntegrityTrustState.NON_APPLICABLE_FOR_POLICY.value: "Non-applicable for policy",
        IntegrityTrustState.RUNTIME_MANIFEST_MISMATCH.value: "Runtime manifest mismatch",
        IntegrityTrustState.RUNTIME_MUTABLE_CHANGE_ONLY.value: "Runtime mutable changes only",
        IntegrityTrustState.VERIFICATION_ERROR.value: "Verification error",
    }.get(trust_state, signature_context_message(source_type, signature_status)[0])


def canonical_trust_state(value: Any) -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "trusted": IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value,
        "verified": IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value,
        "modified": IntegrityTrustState.MODIFIED_UNAPPROVED.value,
        "unknown": IntegrityTrustState.VERIFICATION_ERROR.value,
        "failed": IntegrityTrustState.VERIFICATION_ERROR.value,
    }
    if text in {item.value for item in IntegrityTrustState}:
        return text
    return aliases.get(text, text or IntegrityTrustState.VERIFICATION_ERROR.value)


__all__ = [
    "IntegrityTrustState",
    "SOURCE_DEV_UNSIGNED_MESSAGE",
    "RELEASE_UNSIGNED_MESSAGE",
    "canonical_trust_state",
    "signature_context_message",
    "trust_basis_for_state",
]
