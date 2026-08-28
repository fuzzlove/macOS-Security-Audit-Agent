from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines
from mac_audit_agent.integrity.developer_machine_signing import verify_manifest_bytes_signature
from mac_audit_agent.integrity.manifest_canonicalization import canonicalize_manifest_for_signing
from mac_audit_agent.integrity.manifest_signing import verify_release_key_signature_bundle
from mac_audit_agent.integrity.signing import DEFAULT_PUBLIC_KEY_PATH, load_public_key, verify_signature


@dataclass(slots=True)
class SignatureRoundTripResult:
    status: str
    original_signature_valid: bool
    tampered_signature_rejected: bool
    restored_signature_valid: bool
    public_key_fingerprint: str = ""
    signer_identity: str = ""
    signature_algorithm: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_signature_roundtrip(root: Path, manifest_path: Path, signature_path: Path) -> SignatureRoundTripResult:
    root = Path(root).resolve(strict=False)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    bundle = json.loads(Path(signature_path).read_text(encoding="utf-8"))
    canonical_bytes = canonicalize_manifest_for_signing(manifest)
    tampered_manifest = json.loads(json.dumps(manifest))
    if isinstance(tampered_manifest.get("payload"), dict):
        tampered_manifest["payload"]["_tamper_test"] = True
    else:
        tampered_manifest["_tamper_test"] = True
    tampered_bytes = canonicalize_manifest_for_signing(tampered_manifest)
    signature = base64.b64decode(str(bundle.get("signature_base64", "")))
    signature_model = str(bundle.get("signature_model", ""))
    if signature_model == "trusted_release_key":
        root_public_key = root / DEFAULT_PUBLIC_KEY_PATH
        public_key = load_public_key(root_public_key)
        release_check = verify_release_key_signature_bundle(Path(manifest_path), Path(signature_path), public_key_path=root_public_key)
        original = release_check.get("status") == "verified"
        tampered_rejected = not verify_signature(tampered_bytes, signature, public_key)
        restored = verify_signature(canonical_bytes, signature, public_key)
        signer_identity = "release_key"
    else:
        registry = load_trusted_developer_machines(root)
        machine = registry.find(str(bundle.get("developer_machine_id", "")))
        original = bool(machine and verify_manifest_bytes_signature(machine.public_key_pem, canonical_bytes, signature))
        tampered_rejected = bool(machine and not verify_manifest_bytes_signature(machine.public_key_pem, tampered_bytes, signature))
        restored = bool(machine and verify_manifest_bytes_signature(machine.public_key_pem, canonical_bytes, signature))
        signer_identity = str(bundle.get("developer_machine_id", ""))
    status = "verified" if original and tampered_rejected and restored else "failed"
    return SignatureRoundTripResult(
        status,
        original,
        tampered_rejected,
        restored,
        public_key_fingerprint=str(bundle.get("public_key_fingerprint_sha256", "")),
        signer_identity=signer_identity,
        signature_algorithm=str(bundle.get("signature_algorithm", "")),
    )


__all__ = ["SignatureRoundTripResult", "validate_signature_roundtrip"]
