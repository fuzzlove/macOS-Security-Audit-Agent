from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shlex
import sys
from typing import Any

from mac_audit_agent.integrity.manifest_discovery import ManifestDiscoveryResult, discover_integrity_manifests
from mac_audit_agent.integrity.policy_resolver import IntegrityPolicyResolution, resolve_integrity_policy
from mac_audit_agent.integrity.headless_sentinel import snapshot_headless_imports
from mac_audit_agent.integrity.signing import DEFAULT_PUBLIC_KEY_PATH
from mac_audit_agent.integrity.signed_manifest_validator import SignedManifestValidationResult, validate_signed_manifest
from mac_audit_agent.integrity.status_resolver import IntegrityStatusResult, resolve_integrity_status


@dataclass(slots=True)
class IntegrityAuthoritySnapshot:
    policy: str
    policy_resolution: dict[str, object]
    signed_manifest: dict[str, object]
    status: dict[str, object]
    discovery: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class IntegrityAuthority:
    def __init__(self, root: Path | None = None, policy: str | None = "dev") -> None:
        self.root = Path(root or Path.cwd()).resolve(strict=False)
        self.policy_resolution = resolve_integrity_policy(policy, root=self.root)
        self.policy = self.policy_resolution.policy

    def resolve_policy(self) -> IntegrityPolicyResolution:
        return self.policy_resolution

    def resolve_paths(self) -> IntegrityPolicyResolution:
        return self.policy_resolution

    def discover_legacy_manifests(self) -> ManifestDiscoveryResult:
        return discover_integrity_manifests(self.root)

    def discover_manifests(self) -> ManifestDiscoveryResult:
        return self.discover_legacy_manifests()

    def validate_signed_manifest(self) -> SignedManifestValidationResult:
        return validate_signed_manifest(self.policy, root=self.root)

    def resolve_status(self) -> IntegrityStatusResult:
        return resolve_integrity_status(self.policy, root=self.root)

    def status(self) -> IntegrityStatusResult:
        return self.resolve_status()

    def verify(self, *, strict: bool = False) -> IntegrityStatusResult:
        return self.resolve_status()

    def classify_failure(self, error_or_state: object) -> IntegrityStatusResult:
        if isinstance(error_or_state, IntegrityStatusResult):
            return error_or_state
        return self.resolve_status()

    def repair_and_sign(
        self,
        *,
        author: str,
        reason: str,
        build_id: str = "",
        developer_machine: bool = False,
        migrate_legacy: bool = True,
        exclude_generated: bool = True,
        verify_pre_uat_compatible: bool = True,
        approve_current_source: bool = False,
        typed_confirmation: str = "",
        dry_run: bool = False,
    ):
        from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity

        return repair_and_sign_integrity(
            self.root,
            policy=self.policy,
            author=author,
            reason=reason,
            build_id=build_id,
            developer_machine=developer_machine,
            migrate_legacy=migrate_legacy,
            exclude_generated=exclude_generated,
            verify_pre_uat_compatible=verify_pre_uat_compatible,
            approve_current_source=approve_current_source,
            typed_confirmation=typed_confirmation,
            dry_run=dry_run,
        )

    def snapshot(self) -> IntegrityAuthoritySnapshot:
        return IntegrityAuthoritySnapshot(
            policy=self.policy,
            policy_resolution=self.policy_resolution.to_dict(),
            signed_manifest=self.validate_signed_manifest().to_dict(),
            status=self.resolve_status().to_dict(),
            discovery=self.discover_legacy_manifests().to_dict(),
        )

    def doctor(self) -> dict[str, Any]:
        status = self.resolve_status()
        validation = self.validate_signed_manifest()
        discovery = self.discover_legacy_manifests()
        resolution = self.resolve_policy()
        source_manifest = Path(resolution.source_manifest_path)
        source_signature = Path(resolution.source_signature_path)
        sentinel = snapshot_headless_imports()
        imported_gui_modules = sentinel.imported_gui_modules
        cli_path = resolution.source_manifest_path
        pre_uat_path = resolution.source_manifest_path
        ui_path = resolution.source_manifest_path
        release_path = resolution.source_manifest_path
        signature_details = validation.details.get("signature", {}) if isinstance(validation.details, dict) else {}
        public_key_fingerprint = (
            validation.signing_key_fingerprint
            or str(signature_details.get("public_key_fingerprint_sha256", ""))
            or str(validation.signer_identity.get("public_key_fingerprint_sha256", ""))
        )
        hash_algorithm = ""
        signed_validation = validation.details.get("signed_manifest_validation", {}) if isinstance(validation.details, dict) else {}
        manifest_verification = validation.details.get("manifest_verification", {}) if isinstance(validation.details, dict) else {}
        if isinstance(signed_validation, dict):
            hash_algorithm = str(signed_validation.get("hash_algorithm", ""))
        if not hash_algorithm and isinstance(manifest_verification, dict):
            schema_errors = manifest_verification.get("schema_errors") or []
            hash_algorithm = "sha256" if not schema_errors else ""
        return {
            "policy": self.policy,
            "policy_source": "explicit" if self.policy else "default",
            "canonical_manifest_path": str(source_manifest),
            "canonical_signature_path": str(source_signature),
            "public_key_source": str((self.root / DEFAULT_PUBLIC_KEY_PATH).resolve(strict=False)),
            "public_key_fingerprint": public_key_fingerprint,
            "private_key_required_for_verify": False,
            "signing_algorithm": str(signature_details.get("signature_algorithm") or validation.signer_identity.get("signer_type") or "not_available"),
            "hash_algorithm": hash_algorithm or "sha256",
            "canonical_manifest_exists": source_manifest.exists(),
            "canonical_signature_exists": source_signature.exists(),
            "signature_present": source_signature.exists(),
            "signature_valid": status.signature_valid is True,
            "legacy_manifest_candidates": discovery.discovered_legacy_manifests,
            "legacy_signature_candidates": discovery.discovered_legacy_signatures,
            "cli_verifier_path": cli_path,
            "pre_uat_verifier_path": pre_uat_path,
            "integrity_health_verifier_path": ui_path,
            "release_readiness_verifier_path": release_path,
            "path_consistency": {
                "cli_matches_pre_uat": cli_path == pre_uat_path,
                "cli_matches_ui": cli_path == ui_path,
                "cli_matches_release_readiness": cli_path == release_path,
            },
            "generated_artifact_exclusions_active": bool(status.excluded_files),
            "source_files_checked_count": status.checked_files,
            "excluded_files_count": len(status.excluded_files),
            "modified_source_files": status.source_modified_files,
            "modified_generated_files": status.generated_modified_files,
            "signature_status": "valid" if status.signature_valid is True else "invalid" if status.signature_valid is False else "not_checked",
            "result_code": status.result_code,
            "failure_code": status.failure_code,
            "trust_state": status.trust_state,
            "status": status.status,
            "release_id": status.release_id,
            "build_id": status.build_id,
            "git_commit": status.git_commit,
            "signing_key_fingerprint": status.signing_key_fingerprint or public_key_fingerprint,
            "current_integrity_result": status.result_code,
            "blocking_reason": "" if status.status == "verified" else status.reason,
            "exact_failure_reason": "" if status.status == "verified" else status.reason,
            "suggested_fix": status.recommended_action,
            "exact_remediation_steps": _remediation_steps(status.result_code, status.recommended_action),
            "recommended_repair_command": f"{shlex.quote(sys.executable)} -m mac_audit_agent.integrity repair-and-sign --policy {self.policy} --author \"Liquidsky Network Security\" --reason \"approved development baseline\" --developer-machine --migrate-legacy --exclude-generated --verify-pre-uat-compatible",
            "headless_safe": not imported_gui_modules,
            "imported_gui_modules": imported_gui_modules,
            "pre_uat_compatible": status.pre_uat_compatible,
            "details": status.to_dict(),
        }


def _remediation_steps(result_code: str, recommended_action: str) -> list[str]:
    if result_code == "VALID":
        return ["No remediation required."]
    if result_code in {"MANIFEST_MISSING", "MANIFEST_UNSIGNED", "SIGNATURE_INVALID", "PUBLIC_KEY_MISSING"}:
        return [
            "Do not trust this installation until signed integrity verification passes.",
            "Reinstall from an official release or rebuild from trusted source.",
            recommended_action or "Regenerate and sign the manifest through the authorized release workflow.",
        ]
    if result_code in {"HASH_MISMATCH", "FILE_MISSING", "UNEXPECTED_FILE"}:
        return [
            "Treat the install as tampered until reviewed.",
            "Reinstall from an official release unless the change is explicitly authorized.",
            recommended_action or "Review changed files and sign a new release only from trusted source.",
        ]
    return [
        "Collect the doctor output and logs.",
        "Do not treat the installation as trusted.",
        recommended_action or "Rerun integrity doctor and repair only from trusted source.",
    ]


__all__ = ["IntegrityAuthority", "IntegrityAuthoritySnapshot"]
