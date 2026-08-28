from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.developer_machine_identity import (
    DeveloperMachineIdentity,
    TrustedDeveloperMachineRegistry,
    create_developer_machine_identity,
    current_machine_matches,
    load_trusted_developer_machines,
    revoke_developer_machine,
    write_trusted_developer_machines,
)
from mac_audit_agent.integrity.manifest_canonicalization import CANONICALIZATION_VERSION, canonicalize_manifest_for_signing
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signing import calculate_file_sha256
from mac_audit_agent.version import APP_VERSION


class DeveloperMachineSigningError(RuntimeError):
    pass


@dataclass(slots=True)
class DeveloperMachineSignatureVerification:
    status: str
    trust_state: str
    reason: str
    developer_machine_id: str = ""
    public_key_fingerprint_sha256: str = ""
    signer_status: list[dict[str, Any]] | None = None
    current_machine_is_signer: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "trust_state": self.trust_state,
            "reason": self.reason,
            "developer_machine_id": self.developer_machine_id,
            "public_key_fingerprint_sha256": self.public_key_fingerprint_sha256,
            "signer_status": list(self.signer_status or []),
            "current_machine_is_signer": self.current_machine_is_signer,
        }


def developer_key_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "keys"


def create_developer_machine_key(root: Path, *, developer: str, organization: str, machine_label: str, use_secure_enclave: bool = False) -> DeveloperMachineIdentity:
    root = Path(root).resolve(strict=False)
    key_dir = developer_key_dir()
    key_dir.mkdir(parents=True, exist_ok=True)
    temp_private = key_dir / "developer_machine_p256_private.pending.pem"
    _run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(temp_private)])
    public_pem = _run(["openssl", "ec", "-in", str(temp_private), "-pubout"]).stdout
    fingerprint = hashlib.sha256(public_pem.encode("utf-8")).hexdigest()
    identity = create_developer_machine_identity(
        developer=developer,
        organization=organization,
        machine_label=machine_label,
        public_key_pem=public_pem,
        public_key_fingerprint_sha256=fingerprint,
        signing_key_label=f"MSAA Developer Machine {machine_label}",
        secure_enclave_backed=False,
        keychain_backed=False,
    )
    private_key = _private_key_path(identity.developer_machine_id)
    temp_private.replace(private_key)
    try:
        private_key.chmod(0o600)
    except OSError:
        pass
    registry = load_trusted_developer_machines(root)
    registry.trusted_machines = [machine for machine in registry.trusted_machines if machine.developer_machine_id != identity.developer_machine_id]
    registry.trusted_machines.append(identity)
    write_trusted_developer_machines(registry, root)
    return identity


def enroll_developer_machine(root: Path, *, developer: str, organization: str, machine_label: str, use_secure_enclave: bool = False) -> DeveloperMachineIdentity:
    return create_developer_machine_key(root, developer=developer, organization=organization, machine_label=machine_label, use_secure_enclave=use_secure_enclave)


def get_developer_machine_identity(root: Path, developer_machine_id: str | None = None) -> DeveloperMachineIdentity:
    return _select_identity(load_trusted_developer_machines(root), developer_machine_id)


def create_or_load_signing_key(root: Path, *, developer: str, organization: str, machine_label: str, use_secure_enclave: bool = False) -> DeveloperMachineIdentity:
    try:
        return get_developer_machine_identity(root)
    except DeveloperMachineSigningError:
        return create_developer_machine_key(root, developer=developer, organization=organization, machine_label=machine_label, use_secure_enclave=use_secure_enclave)


def get_developer_machine_public_key(root: Path, developer_machine_id: str | None = None) -> str:
    machine = _select_identity(load_trusted_developer_machines(root), developer_machine_id)
    return machine.public_key_pem


def require_developer_machine_signing_key(root: Path, developer_machine_id: str | None = None) -> DeveloperMachineIdentity:
    """Fail before manifest mutation unless the selected signer can actually sign."""
    registry = load_trusted_developer_machines(root)
    if developer_machine_id:
        machine = _select_identity(registry, developer_machine_id)
    else:
        machine = next(
            (
                candidate
                for candidate in registry.active_machines()
                if current_machine_matches(candidate) and _private_key_path(candidate.developer_machine_id).is_file()
            ),
            None,
        )
        if machine is None:
            raise DeveloperMachineSigningError("developer-machine private key is missing from local Keychain/fallback storage")
    if machine.trust_status != "active":
        raise DeveloperMachineSigningError("developer machine is not active")
    if not current_machine_matches(machine):
        raise DeveloperMachineSigningError("current machine fingerprint does not match enrolled developer machine")
    if not _private_key_path(machine.developer_machine_id).is_file():
        raise DeveloperMachineSigningError("developer-machine private key is missing from local Keychain/fallback storage")
    return machine


def sign_manifest_hash(root: Path, manifest_hash: str, developer_machine_id: str | None = None) -> bytes:
    registry = load_trusted_developer_machines(root)
    machine = _select_identity(registry, developer_machine_id)
    if machine.trust_status != "active":
        raise DeveloperMachineSigningError("developer machine is not active")
    if not current_machine_matches(machine):
        raise DeveloperMachineSigningError("current machine fingerprint does not match enrolled developer machine")
    private_key = _private_key_path(machine.developer_machine_id)
    if not private_key.exists():
        raise DeveloperMachineSigningError("developer-machine private key is missing from local Keychain/fallback storage")
    with tempfile.TemporaryDirectory(prefix="msaa-dev-machine-sign-") as tmp:
        payload = Path(tmp) / "manifest_hash.txt"
        signature = Path(tmp) / "manifest_hash.sig"
        payload.write_text(manifest_hash + "\n", encoding="utf-8")
        _run(["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(payload)])
        return signature.read_bytes()


def sign_manifest_bytes(root: Path, payload_bytes: bytes, developer_machine_id: str | None = None) -> bytes:
    registry = load_trusted_developer_machines(root)
    machine = _select_identity(registry, developer_machine_id)
    if machine.trust_status != "active":
        raise DeveloperMachineSigningError("developer machine is not active")
    if not current_machine_matches(machine):
        raise DeveloperMachineSigningError("current machine fingerprint does not match enrolled developer machine")
    private_key = _private_key_path(machine.developer_machine_id)
    if not private_key.exists():
        raise DeveloperMachineSigningError("developer-machine private key is missing from local Keychain/fallback storage")
    with tempfile.TemporaryDirectory(prefix="msaa-dev-machine-sign-") as tmp:
        payload = Path(tmp) / "canonical_manifest.bin"
        signature = Path(tmp) / "canonical_manifest.sig"
        payload.write_bytes(payload_bytes)
        _run(["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(payload)])
        return signature.read_bytes()


def verify_manifest_signature(public_key_pem: str, manifest_hash: str, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="msaa-dev-machine-verify-") as tmp:
        key = Path(tmp) / "public.pem"
        payload = Path(tmp) / "manifest_hash.txt"
        sig = Path(tmp) / "manifest_hash.sig"
        key.write_text(public_key_pem, encoding="utf-8")
        payload.write_text(manifest_hash + "\n", encoding="utf-8")
        sig.write_bytes(signature)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig), str(payload)], text=True, capture_output=True, check=False, timeout=20)
        return result.returncode == 0 and "Verified OK" in (result.stdout or "")


def verify_manifest_bytes_signature(public_key_pem: str, payload_bytes: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="msaa-dev-machine-verify-") as tmp:
        key = Path(tmp) / "public.pem"
        payload = Path(tmp) / "canonical_manifest.bin"
        sig = Path(tmp) / "canonical_manifest.sig"
        key.write_text(public_key_pem, encoding="utf-8")
        payload.write_bytes(payload_bytes)
        sig.write_bytes(signature)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig), str(payload)], text=True, capture_output=True, check=False, timeout=20)
        return result.returncode == 0 and "Verified OK" in (result.stdout or "")


def sign_canonical_manifest(
    root: Path,
    *,
    manifest_path: Path,
    policy: str,
    author: str,
    reason: str,
    build_id: str = "",
    release_id: str = "",
    developer_machine_id: str | None = None,
) -> Path:
    root = Path(root).resolve(strict=False)
    # Multiple historical identities can legitimately match the same Mac.
    # Select an active current-machine identity that can actually sign instead
    # of taking the oldest matching public identity and failing after rehash.
    machine = require_developer_machine_signing_key(root, developer_machine_id)
    manifest_payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    canonical_bytes = canonicalize_manifest_for_signing(manifest_payload)
    manifest_hash = hashlib.sha256(canonical_bytes).hexdigest()
    signature = sign_manifest_bytes(root, canonical_bytes, machine.developer_machine_id)
    payload = {
        "signature_schema_version": 1,
        "signature_bundle_version": 1,
        "signature_model": "trusted_developer_machine",
        "project": "macOS Security Audit Agent",
        "project_name": "macOS Security Audit Agent",
        "policy": policy,
        "manifest_path": manifest_path.relative_to(root).as_posix() if manifest_path.is_relative_to(root) else str(manifest_path),
        "manifest_sha256": manifest_hash,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "signed_payload": "canonical_manifest_json_bytes",
        "signed_at": utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "git_commit": str(manifest_payload.get("git_commit", "")),
        "app_version": APP_VERSION,
        "signature_algorithm": "ECDSA-P256-SHA256",
        "developer_machine_id": machine.developer_machine_id,
        "developer_name": machine.developer_name,
        "organization": machine.organization,
        "machine_label": machine.machine_label,
        "public_key_fingerprint_sha256": machine.public_key_fingerprint_sha256,
        "build_id": build_id,
        "release_id": release_id,
        "author": author,
        "reason": reason,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "signing_backend": "secure_enclave" if machine.secure_enclave_backed else "keychain" if machine.keychain_backed else "encrypted_local_dev_key",
        "secure_enclave_backed": machine.secure_enclave_backed,
        "keychain_backed": machine.keychain_backed,
        "verification_status": "unchecked",
        "limitations": [
            "Developer-machine signing is not equivalent to YubiKey hardware-token signing.",
            "Verification can prove the manifest was signed by an enrolled key, but not that the developer machine was uncompromised.",
            "This is readiness/evidence support and not CISA, DoD, CMMC, or NIST certification.",
        ],
    }
    signature_path = integrity_manifest_paths(root).canonical_signature_bundle
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signature_path


def verify_developer_machine_signature(root: Path, manifest_path: Path, signature_path: Path) -> DeveloperMachineSignatureVerification:
    root = Path(root).resolve(strict=False)
    if not signature_path.exists():
        return DeveloperMachineSignatureVerification("failed", "signature_missing", "Developer-machine signature bundle is missing.")
    if not manifest_path.exists():
        return DeveloperMachineSignatureVerification("failed", "manifest_missing", "Canonical manifest is missing.")
    try:
        bundle = json.loads(signature_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return DeveloperMachineSignatureVerification("failed", "signature_invalid", f"Signature bundle could not be parsed: {type(exc).__name__}: {exc}")
    if bundle.get("signature_model") != "trusted_developer_machine":
        return DeveloperMachineSignatureVerification("failed", "signature_invalid", "Signature bundle is not a developer-machine signature bundle.")
    try:
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        canonical_bytes = canonicalize_manifest_for_signing(manifest_payload)
        manifest_hash = hashlib.sha256(canonical_bytes).hexdigest()
    except Exception as exc:
        return DeveloperMachineSignatureVerification("failed", "manifest_modified_after_signing", f"Manifest could not be canonicalized: {type(exc).__name__}: {exc}", str(bundle.get("developer_machine_id", "")))
    if bundle.get("manifest_sha256") != manifest_hash:
        return DeveloperMachineSignatureVerification("failed", "manifest_modified_after_signing", "Manifest hash does not match signature bundle.", str(bundle.get("developer_machine_id", "")))
    registry = load_trusted_developer_machines(root)
    developer_machine_id = str(bundle.get("developer_machine_id", ""))
    machine = registry.find(developer_machine_id)
    if machine is None:
        return DeveloperMachineSignatureVerification("failed", "developer_machine_not_enrolled", "Manifest signer is not enrolled in trusted_developer_machines.json.", developer_machine_id)
    if machine.trust_status == "revoked":
        return DeveloperMachineSignatureVerification("failed", "developer_machine_revoked", "Manifest signer developer machine is revoked.", developer_machine_id)
    if machine.trust_status != "active":
        return DeveloperMachineSignatureVerification("failed", "developer_machine_not_enrolled", "Manifest signer developer machine is not active.", developer_machine_id)
    if bundle.get("public_key_fingerprint_sha256") != machine.public_key_fingerprint_sha256:
        return DeveloperMachineSignatureVerification("failed", "signature_invalid", "Signature public key fingerprint does not match registry.", developer_machine_id)
    try:
        signature = base64.b64decode(str(bundle.get("signature_base64", "")))
    except Exception:
        return DeveloperMachineSignatureVerification("failed", "signature_invalid", "Signature value is not valid base64.", developer_machine_id)
    if bundle.get("signed_payload") == "canonical_manifest_json_bytes":
        signature_ok = verify_manifest_bytes_signature(machine.public_key_pem, canonical_bytes, signature)
    else:
        signature_ok = verify_manifest_signature(machine.public_key_pem, manifest_hash, signature)
    if not signature_ok:
        return DeveloperMachineSignatureVerification("failed", "signature_invalid", "Manifest signature does not validate against the enrolled developer-machine public key.", developer_machine_id)
    is_signer = current_machine_matches(machine)
    reason = "MSAA files match a canonical manifest signed by an enrolled developer machine." if is_signer else f"Manifest was signed by trusted developer machine {developer_machine_id}; current machine is verifier only."
    return DeveloperMachineSignatureVerification(
        "verified",
        "trusted_developer_machine_signed_manifest",
        reason,
        developer_machine_id,
        machine.public_key_fingerprint_sha256,
        signer_status=[{"developer_machine_id": developer_machine_id, "status": "valid", "current_machine_is_signer": is_signer}],
        current_machine_is_signer=is_signer,
    )


def rotate_developer_machine_key(root: Path, developer_machine_id: str) -> None:
    revoke_developer_machine(Path(root), developer_machine_id, "key rotation")


def revoke_developer_machine_key(root: Path, developer_machine_id: str, reason: str = "") -> None:
    revoke_developer_machine(Path(root), developer_machine_id, reason)


def export_developer_machine_public_identity(root: Path, developer_machine_id: str | None = None) -> dict[str, Any]:
    machine = _select_identity(load_trusted_developer_machines(root), developer_machine_id)
    return machine.to_dict()


def _select_identity(registry: TrustedDeveloperMachineRegistry, developer_machine_id: str | None = None) -> DeveloperMachineIdentity:
    if developer_machine_id:
        machine = registry.find(developer_machine_id)
        if machine is None:
            raise DeveloperMachineSigningError("developer machine is not enrolled")
        return machine
    active = registry.active_machines()
    if not active:
        raise DeveloperMachineSigningError("developer machine is not enrolled")
    for machine in active:
        if current_machine_matches(machine):
            return machine
    raise DeveloperMachineSigningError("current machine is not enrolled for signing")


def _private_key_path(developer_machine_id: str) -> Path:
    return developer_key_dir() / f"developer_machine_{developer_machine_id}_p256_private.pem"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise DeveloperMachineSigningError((result.stderr or result.stdout or f"command failed: {' '.join(args)}").strip())
    return result


__all__ = [
    "DeveloperMachineSigningError",
    "DeveloperMachineSignatureVerification",
    "create_or_load_signing_key",
    "create_developer_machine_key",
    "enroll_developer_machine",
    "export_developer_machine_public_identity",
    "get_developer_machine_identity",
    "get_developer_machine_public_key",
    "require_developer_machine_signing_key",
    "revoke_developer_machine_key",
    "rotate_developer_machine_key",
    "sign_canonical_manifest",
    "sign_manifest_bytes",
    "sign_manifest_hash",
    "verify_developer_machine_signature",
    "verify_manifest_bytes_signature",
    "verify_manifest_signature",
]
