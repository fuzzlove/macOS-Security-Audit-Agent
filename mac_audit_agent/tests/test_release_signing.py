from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.integrity.release_sign import build_release_manifest, create_artifact_manifest, write_json
from mac_audit_agent.integrity.release_verify import verify_release
from mac_audit_agent.integrity.signing import generate_keypair, sign_manifest, verify_manifest_signature
from mac_audit_agent.integrity.trust_states import IntegrityTrustState


def _git(root: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='mac-audit-agent'\nversion='1.0b'\n", encoding="utf-8")
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "MSAA Test")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "initial")
    return root


def test_ed25519_manifest_signature_verifies_and_wrong_key_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    private_key, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    other_private, other_public = generate_keypair(tmp_path / "other_private.pem", tmp_path / "other_public.pem")
    manifest = build_release_manifest(root, version="1.0b", public_key_path=public_key)
    manifest_path = write_json(manifest, tmp_path / "release_manifest.json")
    sig_path = sign_manifest(manifest_path, private_key=private_key.read_bytes(), signature_path=tmp_path / "release_manifest.sig")
    assert verify_manifest_signature(manifest_path, sig_path, public_key)
    assert not verify_manifest_signature(manifest_path, sig_path, other_public)
    assert other_private.exists()


def test_release_manifest_excludes_itself_and_mutable_files(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    (root / "mac_audit_agent/integrity").mkdir(parents=True, exist_ok=True)
    (root / "mac_audit_agent/integrity/release_manifest.json").write_text("old", encoding="utf-8")
    (root / "runtime.sqlite3").write_text("mutable", encoding="utf-8")
    manifest = build_release_manifest(root, version="1.0b", public_key_path=public_key)
    paths = {item["relative_path"] for item in manifest["files"]}
    assert "mac_audit_agent/integrity/release_manifest.json" not in paths
    assert "runtime.sqlite3" not in paths
    assert "mac_audit_agent/module.py" in paths


def test_changed_file_after_signing_fails_verification(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    private_key, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    manifest = build_release_manifest(root, version="1.0b", public_key_path=public_key)
    manifest_path = write_json(manifest, tmp_path / "release_manifest.json")
    sig_path = sign_manifest(manifest_path, private_key=private_key.read_bytes(), signature_path=tmp_path / "release_manifest.sig")
    ok = verify_release(root, mode="dev", manifest_path=manifest_path, signature_path=sig_path, public_key=public_key, artifact_manifest=tmp_path / "missing-artifacts.json", artifact_signature=tmp_path / "missing-artifacts.sig")
    assert ok.status == "verified"
    (root / "mac_audit_agent/module.py").write_text("VALUE = 2\n", encoding="utf-8")
    tampered = verify_release(root, mode="dev", manifest_path=manifest_path, signature_path=sig_path, public_key=public_key, artifact_manifest=tmp_path / "missing-artifacts.json", artifact_signature=tmp_path / "missing-artifacts.sig")
    assert tampered.status == "failed"
    assert tampered.trust_state == "modified_unapproved"
    assert "mac_audit_agent/module.py" in tampered.modified_files


def test_dev_policy_reports_release_artifacts_non_applicable(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    private_key, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    manifest = build_release_manifest(root, version="1.0b", public_key_path=public_key, mode="dev")
    manifest_path = write_json(manifest, tmp_path / "release_manifest.json")
    sig_path = sign_manifest(manifest_path, private_key=private_key.read_bytes(), signature_path=tmp_path / "release_manifest.sig")

    result = verify_release(root, mode="dev", manifest_path=manifest_path, signature_path=sig_path, public_key=public_key, artifact_manifest=tmp_path / "missing-artifacts.json", artifact_signature=tmp_path / "missing-artifacts.sig")

    assert result.status == "verified"
    assert result.release_artifact_status == "non_applicable_for_policy"
    assert result.policy_mode == "dev"


def test_unsigned_source_mode_is_contextual_not_release_failure(tmp_path: Path) -> None:
    result = verify_release(tmp_path, mode="dev", manifest_path=tmp_path / "missing.json", signature_path=tmp_path / "missing.sig", public_key=tmp_path / "missing-public.pem", artifact_manifest=tmp_path / "missing-artifacts.json", artifact_signature=tmp_path / "missing-artifacts.sig")
    assert result.status == "warning"
    assert result.trust_state == IntegrityTrustState.UNSIGNED_SOURCE_CHECKOUT.value


def test_unsigned_release_mode_blocks_missing_manifest(tmp_path: Path) -> None:
    result = verify_release(tmp_path, mode="public_release", manifest_path=tmp_path / "missing.json", signature_path=tmp_path / "missing.sig", public_key=tmp_path / "missing-public.pem", artifact_manifest=tmp_path / "missing-artifacts.json", artifact_signature=tmp_path / "missing-artifacts.sig")
    assert result.status == "failed"
    assert result.trust_state == IntegrityTrustState.MISSING_MANIFEST.value


def test_signed_artifact_manifest_detects_dist_change(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    private_key, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    manifest = build_release_manifest(root, version="1.0b", public_key_path=public_key)
    manifest_path = write_json(manifest, tmp_path / "release_manifest.json")
    sig_path = sign_manifest(manifest_path, private_key=private_key.read_bytes(), signature_path=tmp_path / "release_manifest.sig")
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "mac_audit_agent-1.0b-py3-none-any.whl"
    wheel.write_text("wheel-v1", encoding="utf-8")
    artifact = create_artifact_manifest(dist, version="1.0b", public_key_path=public_key, root=root)
    artifact_path = write_json(artifact, dist / "MSAA_RELEASE_ARTIFACTS.json")
    artifact_sig = sign_manifest(artifact_path, private_key=private_key.read_bytes(), signature_path=dist / "MSAA_RELEASE_ARTIFACTS.sig")
    ok = verify_release(root, mode="public_release", manifest_path=manifest_path, signature_path=sig_path, public_key=public_key, artifact_manifest=artifact_path, artifact_signature=artifact_sig)
    assert ok.status == "verified"
    wheel.write_text("wheel-v2", encoding="utf-8")
    changed = verify_release(root, mode="public_release", manifest_path=manifest_path, signature_path=sig_path, public_key=public_key, artifact_manifest=artifact_path, artifact_signature=artifact_sig)
    assert changed.status == "failed"
    assert changed.trust_state == IntegrityTrustState.RELEASE_ARTIFACT_MISMATCH.value
