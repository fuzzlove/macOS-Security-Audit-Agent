from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json

from mac_audit_agent.integrity.canonical import manifest_files, signed_payload_from_manifest
from mac_audit_agent.integrity.dev_manifest import iter_protected_files
from mac_audit_agent.integrity.developer_machine_signing import verify_developer_machine_signature
from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path
from mac_audit_agent.integrity.hash_scope import classify_integrity_metadata_path
from mac_audit_agent.integrity.failure_codes import failure_code_for_trust_state
from mac_audit_agent.integrity.manifest_discovery import discover_integrity_manifests
from mac_audit_agent.integrity.manifest_signing import manifest_sha256, verify_release_key_signature_bundle
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.integrity.result_codes import result_code_for_validation
from mac_audit_agent.integrity.signing import calculate_file_sha256


@dataclass(slots=True)
class SignedManifestValidationResult:
    status: str
    trust_state: str
    canonical_manifest_path: str
    signature_path: str
    result_code: str = "INTERNAL_ERROR"
    failure_code: str = ""
    manifest_sha256: str = ""
    signed_manifest_sha256: str = ""
    build_id: str = ""
    release_id: str = ""
    git_commit: str = ""
    signing_key_fingerprint: str = ""
    signature_valid: bool | None = None
    signer_identity: dict[str, Any] = field(default_factory=dict)
    developer_machine_id: str = ""
    source_modified_files: list[str] = field(default_factory=list)
    generated_modified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    checked_files: int = 0
    signer_status: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    recommended_action: str = ""
    can_auto_repair: bool = False
    requires_developer_approval: bool = False
    pre_uat_compatible: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_signed_manifest(policy: str = "dev", *, root: Path | None = None) -> SignedManifestValidationResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    policy = normalize_policy(policy)
    paths = integrity_manifest_paths(root)
    manifest = paths.manifest_for_policy(policy)
    signature = paths.signature_for_policy(policy)
    discovery = discover_integrity_manifests(root)
    generated_dirty, source_dirty = _git_dirty_split(root)
    excluded_files = sorted(set(default_excluded_patterns()))

    base = {
        "canonical_manifest_path": str(manifest),
        "signature_path": str(signature),
        "generated_modified_files": generated_dirty,
        "excluded_files": excluded_files,
        "details": {"discovery": discovery.to_dict(), "policy": policy},
    }

    if not manifest.exists():
        trust = "manifest_path_divergence" if discovery.discovered_legacy_manifests and not signature.exists() else "manifest_missing"
        return SignedManifestValidationResult(
            status="failed",
            trust_state=trust,
            result_code=result_code_for_validation(status="failed", trust_state=trust),
            failure_code=failure_code_for_trust_state(trust),
            reason="Canonical integrity manifest is missing." if trust == "manifest_missing" else "Legacy manifest exists but canonical manifest is missing.",
            recommended_action="Run integrity auto-sign after confirming the source tree is trusted.",
            can_auto_repair=True,
            **base,
        )

    if not signature.exists():
        return SignedManifestValidationResult(
            status="failed",
            trust_state="signature_missing",
            result_code=result_code_for_validation(status="failed", trust_state="signature_missing"),
            failure_code=failure_code_for_trust_state("signature_missing"),
            reason="The canonical integrity manifest exists but has not been signed.",
            recommended_action="Run integrity auto-sign with an enrolled developer-machine key.",
            can_auto_repair=True,
            **base,
        )

    try:
        manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        return SignedManifestValidationResult(
            status="failed",
            trust_state="signature_invalid",
            result_code=result_code_for_validation(status="failed", trust_state="signature_invalid"),
            failure_code=failure_code_for_trust_state("signature_invalid"),
            signature_valid=False,
            reason=f"Manifest could not be parsed: {type(exc).__name__}: {exc}",
            recommended_action="Restore the manifest from a trusted release or regenerate and sign it through the authorized release workflow.",
            details=base["details"],
            **{key: value for key, value in base.items() if key != "details"},
        )
    try:
        current_manifest_sha256 = manifest_sha256(manifest_payload)
        signed_payload = signed_payload_from_manifest(manifest_payload)
    except Exception as exc:
        return SignedManifestValidationResult(
            status="failed",
            trust_state="manifest_modified_after_signing",
            result_code=result_code_for_validation(status="failed", trust_state="manifest_modified_after_signing"),
            failure_code=failure_code_for_trust_state("manifest_modified_after_signing"),
            signature_valid=False,
            reason=f"Manifest signed payload is not canonical: {type(exc).__name__}: {exc}",
            recommended_action=_action_for("manifest_modified_after_signing"),
            requires_developer_approval=True,
            details=base["details"],
            **{key: value for key, value in base.items() if key != "details"},
        )

    try:
        signature_bundle = json.loads(signature.read_text(encoding="utf-8"))
    except Exception as exc:
        return SignedManifestValidationResult(
            status="failed",
            trust_state="signature_invalid",
            result_code=result_code_for_validation(status="failed", trust_state="signature_invalid"),
            failure_code=failure_code_for_trust_state("signature_invalid"),
            signature_valid=False,
            manifest_sha256=current_manifest_sha256,
            build_id=str(signed_payload.get("build_id", "")),
            release_id=str(signed_payload.get("release_id", "")),
            git_commit=str(signed_payload.get("git_commit", "")),
            reason=f"Signature bundle could not be parsed as canonical JSON: {type(exc).__name__}: {exc}",
            recommended_action="Regenerate the detached signature bundle through the authorized release or developer-machine workflow.",
            details=base["details"],
            **{key: value for key, value in base.items() if key != "details"},
        )

    signature_model = str(signature_bundle.get("signature_model", ""))
    release_signature_result: dict[str, Any] | None = None
    sig = None
    if signature_model == "trusted_developer_machine":
        sig = verify_developer_machine_signature(root, manifest, signature)
        signature_details = sig.to_dict()
        signature_ok = sig.status == "verified"
        trust = sig.trust_state
        developer_machine_id = sig.developer_machine_id
        signer_status = sig.signer_status or []
        signer_identity = {
            "developer_machine_id": sig.developer_machine_id,
            "public_key_fingerprint_sha256": sig.public_key_fingerprint_sha256,
            "current_machine_is_signer": sig.current_machine_is_signer,
            "signer_type": "developer_machine",
        }
        reason = sig.reason
        signing_key_fingerprint = sig.public_key_fingerprint_sha256
    elif signature_model == "trusted_release_key":
        release_signature_result = verify_release_key_signature_bundle(manifest, signature)
        signature_details = release_signature_result
        signature_ok = release_signature_result.get("status") == "verified"
        trust = str(release_signature_result.get("trust_state", "signature_invalid"))
        developer_machine_id = ""
        signer_status = [{"signer_type": "release_key", "status": "valid" if signature_ok else "invalid"}]
        signer_identity = {
            "signer_type": "release_key",
            "public_key_fingerprint_sha256": str(release_signature_result.get("public_key_fingerprint_sha256", "")),
        }
        reason = str(release_signature_result.get("reason", ""))
        signing_key_fingerprint = str(release_signature_result.get("public_key_fingerprint_sha256", signature_bundle.get("public_key_fingerprint_sha256", "")))
    else:
        signature_details = {"signature_model": signature_model}
        signature_ok = False
        trust = "signature_invalid"
        developer_machine_id = ""
        signer_status = []
        signer_identity = {}
        reason = "Signature bundle has an unsupported signature_model."
        signing_key_fingerprint = str(signature_bundle.get("public_key_fingerprint_sha256", ""))

    if not signature_ok:
        return SignedManifestValidationResult(
            status="failed",
            trust_state=trust,
            result_code=result_code_for_validation(status="failed", trust_state=trust),
            failure_code=failure_code_for_trust_state(trust),
            manifest_sha256=current_manifest_sha256,
            signed_manifest_sha256=str(signature_bundle.get("manifest_sha256", "")),
            build_id=str(signed_payload.get("build_id", signature_bundle.get("build_id", ""))),
            release_id=str(signed_payload.get("release_id", signature_bundle.get("release_id", ""))),
            git_commit=str(signed_payload.get("git_commit", signature_bundle.get("git_commit", ""))),
            signing_key_fingerprint=signing_key_fingerprint,
            signature_valid=False,
            signer_status=signer_status,
            developer_machine_id=developer_machine_id,
            reason=reason,
            recommended_action=_action_for(trust),
            can_auto_repair=trust in {"signature_missing", "signature_invalid", "manifest_modified_after_signing"},
            requires_developer_approval=trust == "manifest_modified_after_signing",
            details={**base["details"], "signature": signature_details},
            **{key: value for key, value in base.items() if key != "details"},
        )

    file_check = _verify_manifest_file_entries(root, manifest_payload)
    modified = file_check["modified"]
    missing = file_check["missing"]
    extra = file_check["unexpected"]
    schema_errors = file_check["schema_errors"]
    if modified or missing or extra or schema_errors:
        source_files = sorted(set(modified + missing + extra + source_dirty))
        return SignedManifestValidationResult(
            status="failed",
            trust_state="source_files_modified",
            result_code=result_code_for_validation(
                status="failed",
                trust_state="source_files_modified",
                modified_files=modified,
                missing_files=missing,
                extra_files=extra,
            ),
            failure_code=failure_code_for_trust_state("source_files_modified", modified=bool(modified), missing=bool(missing), extra=bool(extra)),
            manifest_sha256=current_manifest_sha256,
            signed_manifest_sha256=str(signature_bundle.get("manifest_sha256", "")),
            build_id=str(signed_payload.get("build_id", signature_bundle.get("build_id", ""))),
            release_id=str(signed_payload.get("release_id", signature_bundle.get("release_id", ""))),
            git_commit=str(signed_payload.get("git_commit", signature_bundle.get("git_commit", ""))),
            signing_key_fingerprint=signing_key_fingerprint,
            signature_valid=True,
            signer_status=signer_status,
            developer_machine_id=developer_machine_id,
            source_modified_files=source_files,
            missing_files=missing,
            extra_files=extra,
            checked_files=int(file_check["checked_files"]),
            reason="Protected source files differ from the signed canonical integrity manifest.",
            recommended_action="Review modified files, then rerun auto-sign with explicit source approval if legitimate.",
            requires_developer_approval=True,
            details={**base["details"], "signature": signature_details, "manifest_verification": file_check},
            **{key: value for key, value in base.items() if key != "details"},
        )

    return SignedManifestValidationResult(
        status="verified",
        trust_state=trust,
        result_code=result_code_for_validation(status="verified", trust_state=trust),
        failure_code="",
        manifest_sha256=current_manifest_sha256,
        signed_manifest_sha256=str(signature_bundle.get("manifest_sha256", "")),
        build_id=str(signed_payload.get("build_id", signature_bundle.get("build_id", ""))),
        release_id=str(signed_payload.get("release_id", signature_bundle.get("release_id", ""))),
        git_commit=str(signed_payload.get("git_commit", signature_bundle.get("git_commit", ""))),
        signing_key_fingerprint=signing_key_fingerprint,
        signature_valid=True,
        signer_identity=signer_identity,
        signer_status=signer_status,
        developer_machine_id=developer_machine_id,
        checked_files=int(file_check["checked_files"]),
        reason=reason,
        recommended_action="No action required for integrity trust.",
        pre_uat_compatible=True,
        details={**base["details"], "signature": signature_details, "manifest_verification": file_check},
        **{key: value for key, value in base.items() if key != "details"},
    )


def _verify_manifest_file_entries(root: Path, manifest_payload: dict[str, Any]) -> dict[str, Any]:
    schema_errors: list[str] = []
    signed_payload = signed_payload_from_manifest(manifest_payload)
    if signed_payload.get("manifest_schema_version") not in {"1", "2", 1, 2, None} and signed_payload.get("schema_version") not in {"1", 1, None}:
        schema_errors.append(f"unsupported manifest schema: {signed_payload.get('manifest_schema_version') or signed_payload.get('schema_version')!r}")
    if signed_payload.get("hash_algorithm", "sha256") != "sha256":
        schema_errors.append(f"unsupported hash algorithm: {signed_payload.get('hash_algorithm')!r}")
    entries = [item for item in manifest_files(manifest_payload) if isinstance(item, dict) and item.get("relative_path")]
    expected = {str(item["relative_path"]).replace("\\", "/").lstrip("./"): item for item in entries}
    observed_paths = {path.relative_to(root).as_posix(): path for path in iter_protected_files(root)}
    modified: list[str] = []
    missing: list[str] = []
    unexpected: list[str] = []
    checked = 0
    details: list[dict[str, str]] = []
    for rel in sorted(expected):
        entry = expected[rel]
        path = root / rel
        if rel not in observed_paths or not path.exists():
            missing.append(rel)
            details.append({"relative_path": rel, "status": "missing", "expected_hash": str(entry.get("sha256", "")), "observed_hash": ""})
            continue
        observed_hash = calculate_file_sha256(path)
        expected_hash = str(entry.get("sha256", ""))
        if observed_hash != expected_hash:
            modified.append(rel)
            details.append({"relative_path": rel, "status": "modified", "expected_hash": expected_hash, "observed_hash": observed_hash})
        else:
            checked += 1
    for rel in sorted(observed_paths):
        if rel not in expected:
            unexpected.append(rel)
            details.append({"relative_path": rel, "status": "unexpected", "expected_hash": "", "observed_hash": calculate_file_sha256(observed_paths[rel])})
    return {
        "ok": not modified and not missing and not unexpected and not schema_errors,
        "checked_files": checked,
        "modified": modified,
        "missing": missing,
        "unexpected": unexpected,
        "schema_errors": schema_errors,
        "findings": details,
    }


def _git_dirty_split(root: Path) -> tuple[list[str], list[str]]:
    try:
        result = subprocess.run(["git", "status", "--porcelain"], cwd=root, text=True, capture_output=True, check=False, timeout=10)
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


def _action_for(trust_state: str) -> str:
    if trust_state == "manifest_modified_after_signing":
        return "Review the manifest and source changes before signing a new approved baseline."
    if trust_state in {"signature_invalid", "signature_missing"}:
        return "Run integrity auto-sign with an enrolled developer-machine key after reviewing source trust."
    if trust_state == "developer_machine_not_enrolled":
        return "Enroll a trusted developer machine before signing."
    if trust_state == "developer_machine_revoked":
        return "Rotate or re-enroll an authorized developer-machine identity."
    return "Review integrity diagnostics and rerun status with --verbose."


__all__ = ["SignedManifestValidationResult", "validate_signed_manifest"]
