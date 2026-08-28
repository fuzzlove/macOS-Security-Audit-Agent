from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path
from mac_audit_agent.integrity.hash_scope import classify_integrity_metadata_path
from mac_audit_agent.integrity.manifest_discovery import discover_integrity_manifests
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.integrity.result_codes import IntegrityResultCode
from mac_audit_agent.integrity.signed_manifest_validator import validate_signed_manifest
from mac_audit_agent.integrity.trust_states import IntegrityTrustState


TRUST_TITLES = {
    "trusted_developer_machine_signed_manifest": "Trusted Developer-Machine Signed Manifest",
    "trusted_release_key_signed_manifest": "Trusted Release-Key Signed Manifest",
    "trusted_dual_yubikey_signed_manifest": "Trusted Dual-YubiKey Signed Manifest",
    "trusted_development_baseline": "Trusted Development Baseline",
    "trusted_signed_release": "Trusted Signed Release",
    "generated_artifact_out_of_scope": "Generated Artifacts Changed",
    "manifest_path_divergence": "Manifest Path Mismatch",
    "manifest_missing": "Missing Integrity Manifest",
    "missing_manifest": "Missing Integrity Manifest",
    "manifest_signature_missing": "Manifest Signature Missing",
    "manifest_signature_invalid": "Manifest Signature Invalid",
    "signature_missing": "Manifest Signature Missing",
    "signature_invalid": "Manifest Signature Invalid",
    "unsigned_manifest": "Unsigned Manifest",
    "manifest_modified_after_signing": "Manifest Modified After Signing",
    "developer_machine_not_enrolled": "Developer Machine Not Enrolled",
    "developer_machine_revoked": "Developer Machine Revoked",
    "machine_fingerprint_mismatch": "Machine Fingerprint Mismatch",
    "source_files_modified": "Source Files Modified",
    "manifest_quorum_missing": "Manifest Signature Quorum Missing",
    "yubikey_required": "YubiKey Required",
    "codex_provenance_unverified": "Codex Provenance Unverified",
    "modified_unapproved": "Unapproved Source Modification",
    "non_applicable_for_policy": "Not Applicable For Policy",
    "verification_error": "Integrity Verification Error",
}

TRUST_MESSAGES = {
    "trusted_developer_machine_signed_manifest": "MSAA files match the canonical integrity manifest signed by an enrolled developer machine.",
    "trusted_release_key_signed_manifest": "MSAA files match the canonical integrity manifest signed by the pinned release public key.",
    "trusted_dual_yubikey_signed_manifest": "MSAA files match the canonical signed manifest. Two enrolled YubiKeys verified the manifest.",
    "trusted_development_baseline": "MSAA source files match the signed development integrity manifest.",
    "trusted_signed_release": "MSAA files match the signed release manifest.",
    "generated_artifact_out_of_scope": "Only generated audit/package artifacts changed. These are excluded from integrity trust decisions.",
    "manifest_path_divergence": "Integrity tools are using different manifest paths. Rebuild using the canonical policy manifest.",
    "manifest_missing": "No canonical integrity manifest exists for the selected policy.",
    "missing_manifest": "No canonical integrity manifest exists for the selected policy.",
    "manifest_signature_missing": "The canonical signature bundle is missing.",
    "manifest_signature_invalid": "The canonical signature bundle is invalid.",
    "signature_missing": "The canonical developer-machine signature bundle is missing.",
    "signature_invalid": "The canonical developer-machine signature bundle is invalid.",
    "unsigned_manifest": "The canonical manifest is unsigned and cannot establish trust.",
    "manifest_modified_after_signing": "The canonical manifest no longer matches the signed manifest hash.",
    "developer_machine_not_enrolled": "No active trusted developer-machine identity can verify this manifest signature.",
    "developer_machine_revoked": "The developer machine that signed this manifest has been revoked.",
    "machine_fingerprint_mismatch": "This Mac is not enrolled for signing trusted manifest changes.",
    "source_files_modified": "Protected source files differ from the canonical integrity manifest.",
    "manifest_quorum_missing": "Two distinct enrolled YubiKey signatures are required.",
    "yubikey_required": "Two enrolled YubiKeys are required before trusted manifest signing.",
    "codex_provenance_unverified": "Codex provenance is metadata-only or missing; cryptographic trust still requires YubiKeys.",
    "modified_unapproved": "Protected source files differ from the selected integrity manifest.",
    "non_applicable_for_policy": "This integrity check does not apply to the selected policy.",
    "verification_error": "MSAA could not complete integrity verification. Review diagnostics.",
}


@dataclass(slots=True)
class IntegrityStatusResult:
    status: str
    trust_state: str
    result_code: str
    failure_code: str
    policy_mode: str
    manifest_path: str
    signature_path: str
    canonical_manifest_path: str
    manifest_exists: bool
    signature_exists: bool
    signature_valid: bool | None
    checked_files: int
    legacy_manifest_paths: list[str] = field(default_factory=list)
    discovered_manifest_paths: list[str] = field(default_factory=list)
    signature_paths: list[str] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    generated_modified_files: list[str] = field(default_factory=list)
    source_modified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    signer_status: list[dict[str, Any]] = field(default_factory=list)
    build_id: str = ""
    release_id: str = ""
    git_commit: str = ""
    signing_key_fingerprint: str = ""
    quorum_status: str = ""
    codex_provenance_status: str = "metadata_only"
    reason: str = ""
    recommended_action: str = ""
    pre_uat_compatible: bool = False
    integrity_health_display_title: str = ""
    integrity_health_display_message: str = ""
    canonical_manifest_used: bool = True
    legacy_manifest_detected: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IntegrityStatusResolver:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or Path.cwd()).resolve(strict=False)

    def resolve_integrity_status(self, policy_mode: str | None = None) -> IntegrityStatusResult:
        try:
            policy = normalize_policy(policy_mode or "dev")
            paths = integrity_manifest_paths(self.root)
            validation = validate_signed_manifest(policy, root=self.root)
            legacy_present = any(Path(path).exists() for path in paths.legacy_manifest_paths)
            return self._result(
                status=validation.status,
                trust_state=validation.trust_state,
                result_code=validation.result_code,
                failure_code=validation.failure_code,
                policy=policy,
                manifest=Path(validation.canonical_manifest_path),
                signature=Path(validation.signature_path),
                signature_valid=validation.signature_valid,
                checked_files=validation.checked_files,
                excluded_files=validation.excluded_files,
                modified_files=validation.source_modified_files,
                generated_modified_files=validation.generated_modified_files,
                source_modified_files=validation.source_modified_files,
                missing_files=validation.missing_files,
                extra_files=validation.extra_files,
                signer_status=validation.signer_status,
                build_id=validation.build_id,
                release_id=validation.release_id,
                git_commit=validation.git_commit,
                signing_key_fingerprint=validation.signing_key_fingerprint,
                quorum_status="not_required",
                reason=validation.reason,
                recommended_action=validation.recommended_action,
                legacy_manifest_detected=legacy_present,
                details=validation.details | {"signed_manifest_validation": validation.to_dict()},
            )
        except Exception as exc:
            policy = normalize_policy(policy_mode or "dev") if str(policy_mode or "dev") in {"dev", "pre_release", "public_release", "runtime", "release"} else "dev"
            paths = integrity_manifest_paths(self.root)
            return self._result(
                status="error",
                trust_state=IntegrityTrustState.VERIFICATION_ERROR.value,
                result_code=IntegrityResultCode.INTERNAL_ERROR.value,
                failure_code="UNKNOWN_UNCLASSIFIED_ERROR",
                policy=policy,
                manifest=paths.manifest_for_policy(policy),
                signature=paths.signature_for_policy(policy),
                checked_files=0,
                reason=f"{type(exc).__name__}: {exc}",
                recommended_action="Review integrity diagnostics and rerun status with --verbose.",
                legacy_manifest_detected=any(path.exists() for path in paths.legacy_manifest_paths),
                details={"exception": type(exc).__name__, "error": str(exc)},
            )

    def _result(
        self,
        *,
        status: str,
        trust_state: str,
        result_code: str,
        failure_code: str,
        policy: str,
        manifest: Path,
        signature: Path,
        checked_files: int,
        signature_valid: bool | None = None,
        excluded_files: list[str] | None = None,
        modified_files: list[str] | None = None,
        generated_modified_files: list[str] | None = None,
        source_modified_files: list[str] | None = None,
        missing_files: list[str] | None = None,
        extra_files: list[str] | None = None,
        signer_status: list[dict[str, Any]] | None = None,
        build_id: str = "",
        release_id: str = "",
        git_commit: str = "",
        signing_key_fingerprint: str = "",
        quorum_status: str = "",
        reason: str = "",
        recommended_action: str = "",
        canonical_manifest_used: bool = True,
        legacy_manifest_detected: bool = False,
        details: dict[str, Any] | None = None,
    ) -> IntegrityStatusResult:
        paths = integrity_manifest_paths(self.root)
        discovery = discover_integrity_manifests(self.root)
        title = TRUST_TITLES.get(trust_state, TRUST_TITLES[IntegrityTrustState.VERIFICATION_ERROR.value])
        message = TRUST_MESSAGES.get(trust_state, TRUST_MESSAGES[IntegrityTrustState.VERIFICATION_ERROR.value])
        pre_uat_compatible = status in {"verified", "warning"} and canonical_manifest_used
        return IntegrityStatusResult(
            status=status,
            trust_state=trust_state,
            result_code=result_code,
            failure_code=failure_code,
            policy_mode=policy,
            manifest_path=str(manifest),
            signature_path=str(signature),
            canonical_manifest_path=str(paths.manifest_for_policy(policy)),
            discovered_manifest_paths=[item.path for item in discovery.discovered if item.exists],
            signature_paths=[str(signature)],
            legacy_manifest_paths=[str(path) for path in paths.legacy_manifest_paths],
            manifest_exists=manifest.exists(),
            signature_exists=signature.exists(),
            signature_valid=signature_valid,
            checked_files=checked_files,
            excluded_files=excluded_files or [],
            modified_files=modified_files or [],
            generated_modified_files=generated_modified_files or [],
            source_modified_files=source_modified_files or [],
            missing_files=missing_files or [],
            extra_files=extra_files or [],
            signer_status=signer_status or [],
            build_id=build_id,
            release_id=release_id,
            git_commit=git_commit,
            signing_key_fingerprint=signing_key_fingerprint,
            quorum_status=quorum_status,
            reason=reason or self._reason_for(trust_state),
            recommended_action=recommended_action or self._action_for(trust_state, policy),
            pre_uat_compatible=pre_uat_compatible,
            integrity_health_display_title=title,
            integrity_health_display_message=message,
            canonical_manifest_used=canonical_manifest_used,
            legacy_manifest_detected=legacy_manifest_detected,
            details=details or {},
        )

    def _git_dirty_split(self) -> tuple[list[str], list[str]]:
        try:
            result = subprocess.run(["git", "status", "--porcelain"], cwd=self.root, text=True, capture_output=True, check=False, timeout=10)
        except Exception:
            return [], []
        generated: list[str] = []
        source: list[str] = []
        for line in result.stdout.splitlines():
            rel = line[3:].strip() if len(line) > 3 else line.strip()
            rel = rel.strip('"')
            if not rel:
                continue
            if classify_integrity_metadata_path(rel):
                continue
            if is_runtime_mutable_path(rel, default_excluded_patterns()):
                generated.append(rel)
            else:
                source.append(rel)
        return sorted(generated), sorted(source)

    @staticmethod
    def _reason_for(trust_state: str) -> str:
        return TRUST_MESSAGES.get(trust_state, TRUST_MESSAGES[IntegrityTrustState.VERIFICATION_ERROR.value])

    @staticmethod
    def _action_for(trust_state: str, policy: str) -> str:
        if trust_state in {"missing_manifest", "manifest_missing", "manifest_path_divergence"}:
            return f"Run integrity discover, then integrity sign --policy {policy} after confirming the source tree is trusted."
        if trust_state in {"invalid_signature", "manifest_signature_missing", "manifest_signature_invalid", "signature_missing", "signature_invalid"}:
            return "Sign the canonical manifest with an enrolled developer-machine key."
        if trust_state in {"developer_machine_not_enrolled", "machine_fingerprint_mismatch"}:
            return "Enroll this developer Mac before signing trusted manifest changes."
        if trust_state == "developer_machine_revoked":
            return "Rotate or re-enroll an authorized developer machine before signing."
        if trust_state in {"manifest_quorum_missing", "yubikey_required"}:
            return "YubiKey signing is optional legacy support; sign with the trusted developer-machine workflow."
        if trust_state in {"modified_unapproved", "source_files_modified"}:
            return "Investigate source drift and require an approved change before signing."
        if trust_state == "generated_artifact_out_of_scope":
            return "Clean generated artifacts or leave them excluded from integrity trust decisions."
        if trust_state in {"trusted_developer_machine_signed_manifest", "trusted_release_key_signed_manifest", "trusted_dual_yubikey_signed_manifest", "trusted_development_baseline", "trusted_signed_release"}:
            return "No action required for integrity trust."
        return "Review integrity diagnostics."


def resolve_integrity_status(policy_mode: str | None = None, *, root: Path | None = None) -> IntegrityStatusResult:
    return IntegrityStatusResolver(root).resolve_integrity_status(policy_mode)


__all__ = ["IntegrityStatusResolver", "IntegrityStatusResult", "resolve_integrity_status"]
