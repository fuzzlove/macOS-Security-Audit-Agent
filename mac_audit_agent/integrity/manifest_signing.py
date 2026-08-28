from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.canonical import canonical_payload_bytes, canonical_payload_sha256
from mac_audit_agent.integrity.developer_machine_signing import sign_canonical_manifest, verify_developer_machine_signature
from mac_audit_agent.integrity.manifest_canonicalization import CANONICALIZATION_VERSION, canonicalize_manifest_for_signing
from mac_audit_agent.integrity.signing import DEFAULT_PUBLIC_KEY_PATH, load_private_key, load_public_key, public_key_id, sign_bytes, verify_signature
from mac_audit_agent.version import APP_VERSION


def canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    return canonical_payload_bytes(manifest)


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return canonical_payload_sha256(manifest)


def sign_manifest(root: Path, manifest_path: Path, *, policy: str, author: str, reason: str, build_id: str = "") -> Path:
    return sign_canonical_manifest(root, manifest_path=manifest_path, policy=policy, author=author, reason=reason, build_id=build_id)


def verify_manifest_signature(root: Path, manifest_path: Path, signature_path: Path):
    return verify_developer_machine_signature(root, manifest_path, signature_path)


def sign_manifest_with_release_key(
    root: Path,
    manifest_path: Path,
    signature_path: Path,
    *,
    private_key_path: Path,
    public_key_path: Path | None = None,
    policy: str,
    author: str,
    reason: str,
    build_id: str = "",
    release_id: str = "",
) -> Path:
    root = Path(root).resolve(strict=False)
    manifest_path = Path(manifest_path).resolve(strict=False)
    signature_path = Path(signature_path).resolve(strict=False)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.get("payload") if isinstance(manifest.get("payload"), dict) else manifest
    canonical_bytes = canonicalize_manifest(manifest)
    manifest_hash = hashlib.sha256(canonical_bytes).hexdigest()
    private_key = load_private_key(private_key_path)
    public_key = load_public_key(_resolve_public_key_path(root, public_key_path))
    signature = sign_bytes(canonical_bytes, private_key)
    bundle = {
        "signature_schema_version": 1,
        "signature_bundle_version": 1,
        "signature_model": "trusted_release_key",
        "project": "macOS Security Audit Agent",
        "project_name": "macOS Security Audit Agent",
        "policy": policy,
        "manifest_path": manifest_path.relative_to(root).as_posix() if manifest_path.is_relative_to(root) else str(manifest_path),
        "manifest_sha256": manifest_hash,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "signed_payload": "canonical_manifest_json_bytes",
        "signed_at": str(payload.get("generated_at", "")),
        "git_commit": str(payload.get("git_commit", "")),
        "app_version": APP_VERSION,
        "signature_algorithm": "ed25519",
        "signer_type": "release_key",
        "public_key_id": public_key_id(public_key),
        "public_key_fingerprint_sha256": hashlib.sha256(public_key).hexdigest(),
        "build_id": build_id or str(payload.get("build_id", "")),
        "release_id": release_id or str(payload.get("release_id", "")),
        "author": author,
        "reason": reason,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "verification_status": "unchecked",
        "limitations": [
            "Release-key manifest signing is an internal tamper-evidence layer and does not replace Apple code signing or notarization.",
            "This is readiness/evidence support and not CISA, DoD, CMMC, or NIST certification.",
        ],
    }
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signature_path


def verify_release_key_signature_bundle(
    manifest_path: Path,
    signature_path: Path,
    *,
    public_key_path: Path | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    signature_path = Path(signature_path)
    if not signature_path.exists():
        return {"status": "failed", "trust_state": "signature_missing", "signature_valid": False, "reason": "Release signature bundle is missing."}
    if not manifest_path.exists():
        return {"status": "failed", "trust_state": "manifest_missing", "signature_valid": False, "reason": "Canonical manifest is missing."}
    try:
        bundle = json.loads(signature_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": f"Signature bundle could not be parsed: {type(exc).__name__}: {exc}"}
    if bundle.get("signature_model") != "trusted_release_key":
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": "Signature bundle is not a trusted release-key bundle."}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        canonical_bytes = canonicalize_manifest(manifest)
        manifest_hash = hashlib.sha256(canonical_bytes).hexdigest()
    except Exception as exc:
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": f"Manifest could not be canonicalized: {type(exc).__name__}: {exc}"}
    if bundle.get("manifest_sha256") != manifest_hash:
        return {
            "status": "failed",
            "trust_state": "manifest_modified_after_signing",
            "signature_valid": False,
            "reason": "Manifest hash does not match release signature bundle.",
            "manifest_sha256": manifest_hash,
            "signed_manifest_sha256": str(bundle.get("manifest_sha256", "")),
        }
    root = _infer_root_from_manifest_path(manifest_path)
    try:
        public_key = load_public_key(_resolve_public_key_path(root, public_key_path))
    except Exception as exc:
        return {"status": "failed", "trust_state": "trusted_public_key_missing", "signature_valid": False, "reason": f"Trusted release public key is missing: {type(exc).__name__}: {exc}"}
    if bundle.get("public_key_fingerprint_sha256") and bundle.get("public_key_fingerprint_sha256") != hashlib.sha256(public_key).hexdigest():
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": "Release public key fingerprint does not match pinned public key."}
    try:
        signature = base64.b64decode(str(bundle.get("signature_base64", "")))
    except Exception:
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": "Release signature value is not valid base64."}
    if not verify_signature(canonical_bytes, signature, public_key):
        return {"status": "failed", "trust_state": "signature_invalid", "signature_valid": False, "reason": "Manifest signature does not validate against the pinned release public key."}
    return {
        "status": "verified",
        "trust_state": "trusted_release_key_signed_manifest",
        "signature_valid": True,
        "reason": "Manifest signature validates against the pinned release public key.",
        "manifest_sha256": manifest_hash,
        "signed_manifest_sha256": str(bundle.get("manifest_sha256", "")),
        "public_key_fingerprint_sha256": hashlib.sha256(public_key).hexdigest(),
        "signature_algorithm": str(bundle.get("signature_algorithm", "ed25519")),
        "signer_type": "release_key",
    }


def _resolve_public_key_path(root: Path, public_key_path: Path | None) -> Path:
    if public_key_path is not None:
        candidate = Path(public_key_path).expanduser()
        return candidate if candidate.is_absolute() else root / candidate
    return root / DEFAULT_PUBLIC_KEY_PATH


def _infer_root_from_manifest_path(manifest_path: Path) -> Path:
    manifest_path = Path(manifest_path).resolve(strict=False)
    parts = manifest_path.parts
    suffix = ("mac_audit_agent", "integrity", "integrity_manifest.json")
    if len(parts) >= 3 and tuple(parts[-3:]) == suffix:
        return Path(*parts[:-3])
    return manifest_path.parent


__all__ = [
    "canonicalize_manifest",
    "manifest_sha256",
    "sign_manifest",
    "sign_manifest_with_release_key",
    "verify_manifest_signature",
    "verify_release_key_signature_bundle",
]
