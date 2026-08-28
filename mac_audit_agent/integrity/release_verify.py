from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.release_policy import release_policy
from mac_audit_agent.integrity.release_sign import DEFAULT_ARTIFACT_MANIFEST, DEFAULT_ARTIFACT_SIGNATURE, DEFAULT_RELEASE_MANIFEST, DEFAULT_RELEASE_SIGNATURE
from mac_audit_agent.integrity.signing import calculate_file_sha256, verify_manifest_signature
from mac_audit_agent.integrity.signature_bundle import verify_signature_bundle
from mac_audit_agent.integrity.trust_states import IntegrityTrustState
from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.version import APP_VERSION
from mac_audit_agent.runtime.force_mode import ForceArgumentError, ForceMode, log_force_action, parse_force_argument


@dataclass
class ReleaseVerificationResult:
    status: str
    trust_state: str
    app_version: str = ""
    git_commit: str = ""
    manifest_path: str = ""
    signature_path: str = ""
    checked_files: int = 0
    modified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    release_artifact_status: str = "not_checked"
    evidence_status: str = "not_checked"
    policy_mode: str = "dev"
    legacy_manifest_detected: bool = False
    canonical_manifest_used: bool = True
    recommended_action: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_release(root: Path, *, mode: str, manifest_path: Path, signature_path: Path, public_key: Path, artifact_manifest: Path, artifact_signature: Path) -> ReleaseVerificationResult:
    normalized_mode = normalize_policy(mode)
    policy = release_policy(normalized_mode)
    root = Path(root).resolve(strict=False)
    paths = integrity_manifest_paths(root)
    canonical_manifest = paths.manifest_for_policy(normalized_mode)
    canonical_signature = paths.signature_for_policy(normalized_mode)
    result = ReleaseVerificationResult(
        status="failed",
        trust_state=IntegrityTrustState.VERIFICATION_ERROR.value,
        manifest_path=str(manifest_path),
        signature_path=str(signature_path),
        policy_mode=policy.mode,
        legacy_manifest_detected=any(path.exists() for path in paths.legacy_manifest_paths),
        canonical_manifest_used=Path(manifest_path).resolve(strict=False) == canonical_manifest.resolve(strict=False)
        and Path(signature_path).resolve(strict=False) == canonical_signature.resolve(strict=False),
    )
    if not manifest_path.exists():
        if policy.signed_manifest_required:
            result.trust_state = IntegrityTrustState.MISSING_MANIFEST.value
            result.recommended_action = "Generate and sign the release manifest."
            return result
        result.status = "warning"
        result.trust_state = IntegrityTrustState.UNSIGNED_SOURCE_CHECKOUT.value
        if policy.mode == "dev":
            result.release_artifact_status = "non_applicable_for_policy"
            result.evidence_status = "non_applicable_for_policy"
        result.recommended_action = "Source checkout is unsigned; create a development baseline or signed release before distribution."
        return result
    if signature_path.exists() and signature_path.name.endswith((".signature.json", ".signatures.json")):
        bundle = verify_signature_bundle(manifest_path, signature_path, policy_mode=policy.mode)
        signature_valid = bundle.status == "verified"
        result.details["signature_bundle"] = bundle.to_dict()
    else:
        signature_valid = verify_manifest_signature(manifest_path, signature_path, public_key) if signature_path.exists() else False
    if policy.mode == "dev":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_exclusions = manifest.get("exclusions") or manifest.get("excluded_runtime_scope") or []
        exclusions = sorted({str(item) for item in manifest_exclusions if isinstance(item, str)} | set(default_excluded_patterns()))
        for entry in manifest.get("files", []):
            if not isinstance(entry, dict):
                continue
            rel = str(entry.get("relative_path", ""))
            if is_runtime_mutable_path(rel, exclusions):
                result.excluded_files.append(rel)
                continue
            path = root / rel
            if not path.exists():
                result.missing_files.append(rel)
                continue
            result.checked_files += 1
            if path.is_file() and calculate_file_sha256(path) != str(entry.get("sha256", "")):
                result.modified_files.append(rel)
        result.release_artifact_status = "non_applicable_for_policy"
        result.evidence_status = "non_applicable_for_policy"
        result.details = {"signature_valid": signature_valid, "policy_mode": policy.mode, "status": "non_applicable_for_policy"}
        if not result.modified_files and not result.missing_files and not result.extra_files:
            result.status = "verified"
            result.trust_state = IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value
            result.recommended_action = "Development integrity baseline verified; release artifact checks are non_applicable_for_policy."
        else:
            result.status = "failed"
            result.trust_state = "modified_unapproved"
            result.recommended_action = "Investigate development source drift and rehash only after approving the source change."
        return result
    if policy.signed_manifest_required and not signature_path.exists():
        result.trust_state = IntegrityTrustState.SIGNATURE_MISSING.value
        result.recommended_action = "Sign the release manifest."
        return result
    if policy.signed_manifest_required and not signature_valid:
        result.trust_state = IntegrityTrustState.SIGNATURE_INVALID.value
        result.recommended_action = "Verify the public key and regenerate the signed release manifest from a trusted tree."
        return result
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result.app_version = str(manifest.get("app_version", ""))
    result.git_commit = str(manifest.get("git_commit", ""))
    if result.app_version and result.app_version != APP_VERSION:
        result.trust_state = IntegrityTrustState.STALE_MANIFEST.value
        result.recommended_action = f"Manifest version {result.app_version} does not match package version {APP_VERSION}."
        return result
    manifest_exclusions = manifest.get("exclusions", [])
    exclusions = sorted({str(item) for item in manifest_exclusions if isinstance(item, str)} | set(default_excluded_patterns()))
    for entry in manifest.get("files", []):
        if not isinstance(entry, dict):
            continue
        rel = str(entry.get("relative_path", ""))
        if is_runtime_mutable_path(rel, exclusions):
            result.excluded_files.append(rel)
            continue
        path = root / rel
        if not path.exists():
            result.missing_files.append(rel)
            continue
        result.checked_files += 1
        if path.is_file() and calculate_file_sha256(path) != str(entry.get("sha256", "")):
            result.modified_files.append(rel)
    if result.modified_files or result.missing_files:
        result.trust_state = IntegrityTrustState.RELEASE_ARTIFACT_MISMATCH.value
        result.recommended_action = "Files differ from the signed release manifest. Rebuild from trusted source or investigate tampering."
        return result
    artifact_ok = True
    if policy.signed_artifacts_required:
        artifact_ok = artifact_manifest.exists() and artifact_signature.exists() and verify_manifest_signature(artifact_manifest, artifact_signature, public_key)
        if not artifact_ok:
            result.release_artifact_status = "missing_or_invalid"
            result.trust_state = IntegrityTrustState.UNSIGNED_RELEASE_ARTIFACT.value
            result.recommended_action = "Build final dist files and sign the artifact manifest."
            return result
        artifact_payload = json.loads(artifact_manifest.read_text(encoding="utf-8"))
        mismatches = []
        for item in artifact_payload.get("artifacts", []):
            path = Path(str(item.get("path", "")))
            if not path.exists() or calculate_file_sha256(path) != str(item.get("sha256", "")):
                mismatches.append(str(item.get("filename", path)))
        if mismatches:
            result.release_artifact_status = "mismatch"
            result.modified_files.extend(mismatches)
            result.trust_state = IntegrityTrustState.RELEASE_ARTIFACT_MISMATCH.value
            result.recommended_action = "Dist artifacts changed after signing. Re-run sign-artifacts on final upload files."
            return result
        result.release_artifact_status = "verified"
    else:
        result.release_artifact_status = "not_required"
    result.status = "verified"
    baseline_mode = str(manifest.get("baseline_mode", policy.mode))
    if signature_valid and baseline_mode == "dev":
        result.trust_state = IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value
    elif signature_valid:
        result.trust_state = IntegrityTrustState.TRUSTED_SIGNED_RELEASE.value
    else:
        result.trust_state = IntegrityTrustState.UNSIGNED_SOURCE_CHECKOUT.value
    result.evidence_status = "present" if Path(f"docs/releases/release_evidence_{result.app_version}.json").exists() else "not_recorded"
    result.recommended_action = "Release integrity verified." if result.status == "verified" else "Review release integrity."
    result.details = {"signature_valid": signature_valid, "policy_mode": policy.mode}
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify signed MSAA release integrity manifests.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--policy", "--mode", dest="mode", default="dev", choices=["dev", "pre_release", "public_release", "release"])
    parser.add_argument("--strict", action="store_true", help="Alias for --mode public_release.")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--signature", type=Path, default=None)
    parser.add_argument("--public-key", type=Path, default=Path("mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem"))
    parser.add_argument("--artifact-manifest", type=Path, default=DEFAULT_ARTIFACT_MANIFEST)
    parser.add_argument("--artifact-signature", type=Path, default=DEFAULT_ARTIFACT_SIGNATURE)
    parser.add_argument("--force", "-f", action="store_true", help="Rerun release verification from scratch. Does not trust new hashes or rebaseline.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cleaned, force_mode = parse_force_argument(raw_argv, command="integrity release verify", supported_scopes={"diagnostics"}, default_scope="diagnostics", require_command=False)
    except ForceArgumentError as exc:
        print(str(exc), file=sys.stderr)
        log_force_action("integrity release verify", ForceMode(enabled=False, scope="unsupported"), result="rejected", error=str(exc))
        return 2
    args = build_parser().parse_args(cleaned)
    if args.force:
        force_mode.enabled = True
    if force_mode.enabled:
        log_force_action("integrity release verify", force_mode, action_taken="rerun_release_verification_without_rebaseline", result="started")
        print("Force enabled: release verification will rerun from current files. New hashes will not be trusted automatically.", file=sys.stderr)
    mode = normalize_policy("public_release" if args.strict else args.mode)
    paths = integrity_manifest_paths(args.root.resolve(strict=False))
    if args.manifest is None:
        args.manifest = paths.manifest_for_policy(mode)
    if args.signature is None:
        args.signature = paths.signature_for_policy(mode)
    result = verify_release(args.root, mode=mode, manifest_path=args.manifest, signature_path=args.signature, public_key=args.public_key, artifact_manifest=args.artifact_manifest, artifact_signature=args.artifact_signature)
    if force_mode.enabled:
        log_force_action("integrity release verify", force_mode, action_taken="rerun_release_verification_without_rebaseline", result=result.status)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
