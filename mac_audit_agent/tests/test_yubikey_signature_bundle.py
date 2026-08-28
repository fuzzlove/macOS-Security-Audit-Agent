from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, resolve_signature_path
from mac_audit_agent.integrity.signature_bundle import verify_signature_bundle
from mac_audit_agent.integrity.signing import calculate_file_sha256
from mac_audit_agent.integrity.trust_policy import EnrolledYubiKey, TrustPolicy, write_trust_policy


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("print('ok')\n", encoding="utf-8")


def _openssl(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openssl", *args], cwd=cwd, text=True, capture_output=True, check=True)


def _keypair(root: Path, name: str) -> tuple[Path, Path]:
    private_key = root / f"{name}_private.pem"
    public_key = root / f"{name}_public.pem"
    _openssl(["genrsa", "-out", str(private_key), "2048"], root)
    pub = _openssl(["rsa", "-in", str(private_key), "-pubout"], root)
    public_key.write_text(pub.stdout, encoding="utf-8")
    return private_key, public_key


def test_canonical_manifest_resolves_to_signature_bundle(tmp_path: Path) -> None:
    paths = integrity_manifest_paths(tmp_path)
    assert resolve_signature_path(tmp_path, "dev", manifest=paths.canonical_manifest) == paths.canonical_signature_bundle


def test_external_dual_yubikey_bundle_verifies_with_two_rsa_signatures(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = rehash_manifest(
        tmp_path,
        author="Liquidsky Network Security",
        reason="dual yubikey test",
        developer_mode=True,
        audit_log=tmp_path / "audit.jsonl",
    )
    paths = integrity_manifest_paths(tmp_path)
    sign_dir = tmp_path / "mac_audit_agent" / "integrity" / "yubikey_signatures"
    sign_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "project": "macOS Security Audit Agent",
        "developer": "Liquidsky Network Security",
        "policy": "dev",
        "build_id": "test-build",
        "git_commit": "unknown",
        "manifest_path": manifest.relative_to(tmp_path).as_posix(),
        "manifest_sha256": calculate_file_sha256(manifest),
        "created_at": "2026-07-08T00:00:00Z",
        "signature_purpose": "MSAA integrity manifest approval",
    }
    payload_path = sign_dir / "signing_payload.json"
    payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    signatures = []
    enrolled = []
    for index in (1, 2):
        private_key, public_key = _keypair(sign_dir, f"yubikey{index}")
        sig_path = sign_dir / f"yubikey{index}_manifest.sig"
        _openssl(["dgst", "-sha256", "-sign", str(private_key), "-out", str(sig_path), str(payload_path)], tmp_path)
        cert_sha = calculate_file_sha256(public_key)
        enrolled.append(
            EnrolledYubiKey(
                yubikey_id=cert_sha[:16],
                label=f"Liquidsky MSAA Signing Key {index}",
                owner_developer_id="liquidsky-network-security",
                public_key_pem=public_key.read_text(encoding="utf-8"),
                certificate_fingerprint_sha256=cert_sha,
                piv_slot="9c",
                status="active",
            )
        )
        signatures.append(
            {
                "signer_label": f"Liquidsky MSAA Signing Key {index}",
                "developer_id": "liquidsky-network-security",
                "yubikey_id": cert_sha[:16],
                "piv_slot": "9c",
                "algorithm": "RSA-SHA256",
                "certificate_sha256": cert_sha,
                "public_key_path": public_key.relative_to(tmp_path).as_posix(),
                "signature_path": sig_path.relative_to(tmp_path).as_posix(),
                "signature_base64": base64.b64encode(sig_path.read_bytes()).decode("ascii"),
            }
        )

    write_trust_policy(TrustPolicy(enrolled_yubikeys=enrolled), tmp_path)
    bundle = {
        "signature_bundle_version": 1,
        "project": "macOS Security Audit Agent",
        "developer": "Liquidsky Network Security",
        "policy": "dev",
        "manifest_path": manifest.relative_to(tmp_path).as_posix(),
        "manifest_sha256": calculate_file_sha256(manifest),
        "signed_payload_path": payload_path.relative_to(tmp_path).as_posix(),
        "signed_payload_sha256": calculate_file_sha256(payload_path),
        "build_id": "test-build",
        "git_commit": "unknown",
        "signed_at": "2026-07-08T00:00:01Z",
        "required_quorum": {"required_count": 2, "require_distinct_devices": True, "slot": "9c"},
        "signatures": signatures,
    }
    paths.canonical_signature_bundle.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = verify_signature_bundle(manifest, paths.canonical_signature_bundle, policy_mode="dev")
    assert result.status == "verified"
    assert result.trust_state == "trusted_dual_yubikey_signed_manifest"
    assert result.valid_signature_count == 2
