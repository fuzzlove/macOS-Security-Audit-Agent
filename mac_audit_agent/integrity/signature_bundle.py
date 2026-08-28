from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.signing import calculate_file_sha256, canonical_json_bytes, verify_signature
from mac_audit_agent.integrity.trust_policy import TrustPolicy, load_trust_policy
from mac_audit_agent.integrity.developer_machine_signing import verify_developer_machine_signature


@dataclass(slots=True)
class SignatureEntry:
    signature_id: str
    yubikey_id: str
    developer_id: str
    signer_label: str
    certificate_fingerprint_sha256: str
    piv_slot: str
    algorithm: str
    signature_base64: str
    signed_payload_hash: str
    signed_at: str
    verification_status: str = "unchecked"


@dataclass(slots=True)
class SignatureBundle:
    signature_bundle_version: str
    manifest_path: str
    manifest_sha256: str
    build_id: str
    git_commit: str
    app_version: str
    signed_at: str
    signing_policy: str
    required_quorum: dict[str, Any]
    signatures: list[SignatureEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signatures"] = [asdict(item) for item in self.signatures]
        return data


@dataclass(slots=True)
class SignatureBundleVerification:
    status: str
    trust_state: str
    reason: str
    valid_signature_count: int
    required_signature_count: int
    signer_status: list[dict[str, Any]] = field(default_factory=list)
    quorum_status: str = "missing"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def signed_payload(*, manifest_sha256: str, build_id: str, git_commit: str, app_version: str, policy_mode: str, project_name: str, approved_change_id: str = "", codex_provenance_id: str = "") -> dict[str, Any]:
    return {
        "manifest_sha256": manifest_sha256,
        "build_id": build_id,
        "git_commit": git_commit,
        "app_version": app_version,
        "policy_mode": policy_mode,
        "project_name": project_name,
        "approved_change_id": approved_change_id,
        "codex_provenance_id": codex_provenance_id,
    }


def payload_hash(payload: dict[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def load_signature_bundle(path: Path) -> SignatureBundle | None:
    if not Path(path).exists():
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    signatures = [SignatureEntry(**item) for item in payload.get("signatures", [])]
    payload = {key: value for key, value in payload.items() if key != "signatures"}
    return SignatureBundle(signatures=signatures, **payload)


def write_signature_bundle(bundle: SignatureBundle, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def verify_signature_bundle(manifest_path: Path, bundle_path: Path, *, trust_policy: TrustPolicy | None = None, policy_mode: str = "dev") -> SignatureBundleVerification:
    manifest_path = Path(manifest_path)
    bundle_path = Path(bundle_path)
    root = manifest_path.parents[2] if len(manifest_path.parents) > 2 else Path.cwd()
    policy = trust_policy or load_trust_policy(root)
    required = policy.required_count
    if not bundle_path.exists():
        return SignatureBundleVerification("failed", "signature_missing", "Signature bundle is missing.", 0, required)
    if not manifest_path.exists():
        return SignatureBundleVerification("failed", "manifest_missing", "Canonical manifest is missing.", 0, required)
    try:
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", f"Signature bundle could not be parsed: {exc}", 0, required)
    if raw.get("signature_model") == "trusted_developer_machine":
        machine = verify_developer_machine_signature(root, manifest_path, bundle_path)
        return SignatureBundleVerification(
            machine.status,
            machine.trust_state,
            machine.reason,
            1 if machine.status == "verified" else 0,
            1,
            machine.signer_status or [],
            "satisfied" if machine.status == "verified" else "missing",
        )
    if _is_external_yubikey_bundle(raw):
        return _verify_external_yubikey_bundle(manifest_path, bundle_path, raw, policy=policy, policy_mode=policy_mode, root=root)
    try:
        bundle = load_signature_bundle(bundle_path)
    except Exception as exc:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", f"Signature bundle could not be parsed: {exc}", 0, required)
    if bundle is None:
        return SignatureBundleVerification("failed", "manifest_signature_missing", "Signature bundle is missing.", 0, required)
    manifest_sha = calculate_file_sha256(manifest_path)
    if bundle.manifest_sha256 != manifest_sha:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signature bundle manifest hash does not match canonical manifest.", 0, required)
    payload = signed_payload(
        manifest_sha256=manifest_sha,
        build_id=bundle.build_id,
        git_commit=bundle.git_commit,
        app_version=bundle.app_version,
        policy_mode=policy_mode,
        project_name=policy.project_name,
    )
    expected_payload_hash = payload_hash(payload)
    enrolled = {key.yubikey_id: key for key in policy.active_yubikeys()}
    signer_status: list[dict[str, Any]] = []
    valid_ids: set[str] = set()
    for entry in bundle.signatures:
        status = "invalid"
        reason = ""
        key = enrolled.get(entry.yubikey_id)
        if key is None:
            reason = "unknown_or_revoked_yubikey"
        elif entry.signed_payload_hash != expected_payload_hash:
            reason = "payload_hash_mismatch"
        elif not key.public_key_pem:
            reason = "missing_public_key"
        else:
            try:
                signature = base64.b64decode(entry.signature_base64)
                if verify_signature(canonical_json_bytes(payload), signature, key.public_key_pem.encode("utf-8")):
                    status = "valid"
                    reason = "verified"
                    valid_ids.add(entry.yubikey_id)
                else:
                    reason = "signature_verify_failed"
            except Exception as exc:
                reason = f"verification_error:{type(exc).__name__}"
        signer_status.append({"yubikey_id": entry.yubikey_id, "developer_id": entry.developer_id, "status": status, "reason": reason})
    if policy.require_distinct_devices and len(valid_ids) < required:
        return SignatureBundleVerification("failed", "manifest_quorum_missing", "Two distinct enrolled YubiKey signatures are required.", len(valid_ids), required, signer_status, "missing")
    return SignatureBundleVerification("verified", "trusted_dual_yubikey_signed_manifest", "Canonical manifest is signed by the required YubiKey quorum.", len(valid_ids), required, signer_status, "satisfied")


def _is_external_yubikey_bundle(payload: dict[str, Any]) -> bool:
    return bool(payload.get("signed_payload_path") or any(isinstance(item, dict) and item.get("algorithm") == "RSA-SHA256" for item in payload.get("signatures", [])))


def _verify_external_yubikey_bundle(
    manifest_path: Path,
    bundle_path: Path,
    payload: dict[str, Any],
    *,
    policy: TrustPolicy,
    policy_mode: str,
    root: Path,
) -> SignatureBundleVerification:
    required = int((payload.get("required_quorum") or {}).get("required_count") or policy.required_count)
    manifest_sha = calculate_file_sha256(manifest_path)
    if payload.get("manifest_sha256") != manifest_sha:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signature bundle manifest hash does not match canonical manifest.", 0, required)
    signed_payload_path = _resolve_bundle_path(root, bundle_path, str(payload.get("signed_payload_path", "")))
    if not signed_payload_path.exists():
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signed payload file is missing.", 0, required)
    signed_payload_bytes = signed_payload_path.read_bytes()
    if payload.get("signed_payload_sha256") and payload.get("signed_payload_sha256") != _sha256(signed_payload_bytes):
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signed payload hash does not match bundle metadata.", 0, required)
    try:
        signed_payload = json.loads(signed_payload_bytes.decode("utf-8"))
    except Exception as exc:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", f"Signed payload could not be parsed: {exc}", 0, required)
    if signed_payload.get("manifest_sha256") != manifest_sha:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signed payload does not bind the canonical manifest hash.", 0, required)
    if signed_payload.get("policy") not in {"", None, policy_mode}:
        return SignatureBundleVerification("failed", "manifest_signature_invalid", "Signed payload policy does not match requested policy.", 0, required)

    enrolled_by_id = {key.yubikey_id: key for key in policy.active_yubikeys()}
    enrolled_by_cert = {key.certificate_fingerprint_sha256: key for key in policy.active_yubikeys() if key.certificate_fingerprint_sha256}
    signer_status: list[dict[str, Any]] = []
    valid_ids: set[str] = set()
    for entry in payload.get("signatures", []):
        if not isinstance(entry, dict):
            continue
        signer_key = str(entry.get("yubikey_id") or "")
        cert_sha = str(entry.get("certificate_sha256") or "")
        key = enrolled_by_id.get(signer_key) or enrolled_by_cert.get(cert_sha)
        status = "invalid"
        reason = ""
        if key is None:
            reason = "unknown_or_revoked_yubikey"
        elif str(entry.get("piv_slot", "")).lower() != "9c":
            reason = "wrong_piv_slot"
        elif str(entry.get("algorithm", "")).upper() != "RSA-SHA256":
            reason = "unsupported_algorithm"
        else:
            public_key_pem = key.public_key_pem
            public_key_path = _resolve_bundle_path(root, bundle_path, str(entry.get("public_key_path", "")))
            if public_key_path.exists():
                public_key_pem = public_key_path.read_text(encoding="utf-8")
            signature_bytes = _signature_bytes(root, bundle_path, entry)
            if not public_key_pem:
                reason = "missing_public_key"
            elif not signature_bytes:
                reason = "missing_signature"
            elif _verify_rsa_sha256(public_key_pem.encode("utf-8"), signature_bytes, signed_payload_bytes):
                status = "valid"
                reason = "verified"
                valid_ids.add(key.yubikey_id)
            else:
                reason = "signature_verify_failed"
        signer_status.append(
            {
                "yubikey_id": signer_key or (key.yubikey_id if key else ""),
                "developer_id": str(entry.get("developer_id", "")),
                "signer_label": str(entry.get("signer_label", "")),
                "status": status,
                "reason": reason,
            }
        )
    if policy.require_distinct_devices and len(valid_ids) < required:
        return SignatureBundleVerification("failed", "manifest_quorum_missing", "Two distinct enrolled YubiKey signatures are required.", len(valid_ids), required, signer_status, "missing")
    if len(valid_ids) < required:
        return SignatureBundleVerification("failed", "manifest_quorum_missing", "Required YubiKey signature quorum was not satisfied.", len(valid_ids), required, signer_status, "missing")
    return SignatureBundleVerification("verified", "trusted_dual_yubikey_signed_manifest", "Canonical manifest is signed by the required YubiKey quorum.", len(valid_ids), required, signer_status, "satisfied")


def _resolve_bundle_path(root: Path, bundle_path: Path, value: str) -> Path:
    if not value:
        return bundle_path.parent / "__missing__"
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    root_candidate = root / path
    if root_candidate.exists() or str(value).startswith("mac_audit_agent/"):
        return root_candidate
    return bundle_path.parent / path


def _signature_bytes(root: Path, bundle_path: Path, entry: dict[str, Any]) -> bytes:
    if entry.get("signature_base64"):
        try:
            return base64.b64decode(str(entry["signature_base64"]))
        except Exception:
            return b""
    signature_path = _resolve_bundle_path(root, bundle_path, str(entry.get("signature_path", "")))
    return signature_path.read_bytes() if signature_path.exists() else b""


def _verify_rsa_sha256(public_key: bytes, signature: bytes, payload: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="msaa-yubikey-verify-") as tmp:
        tmpdir = Path(tmp)
        key_path = tmpdir / "public.pem"
        sig_path = tmpdir / "payload.sig"
        payload_path = tmpdir / "payload.json"
        key_path.write_bytes(public_key)
        sig_path.write_bytes(signature)
        payload_path.write_bytes(payload)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(key_path), "-signature", str(sig_path), str(payload_path)],
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        return result.returncode == 0 and "Verified OK" in (result.stdout or "")


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


__all__ = [
    "SignatureBundle",
    "SignatureBundleVerification",
    "SignatureEntry",
    "load_signature_bundle",
    "payload_hash",
    "signed_payload",
    "verify_signature_bundle",
    "write_signature_bundle",
]
