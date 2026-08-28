from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.exclusions import default_exclusion_entries
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signature_bundle import SignatureBundle, SignatureEntry, payload_hash, signed_payload, write_signature_bundle
from mac_audit_agent.integrity.signing import SigningError, calculate_file_sha256, canonical_json_bytes, generate_keypair, sign_bytes
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status
from mac_audit_agent.integrity.trust_policy import EnrolledYubiKey, TrustPolicy, write_trust_policy
from mac_audit_agent.integrity.wrapper_adapter import default_wrapper_policy


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='msaa-test'\n", encoding="utf-8")


def test_status_resolver_dev_uses_canonical_manifest_and_requires_developer_machine_signature(tmp_path: Path) -> None:
    _write_project(tmp_path)
    rehash_manifest(tmp_path, author="A", reason="R", policy="dev", audit_log=tmp_path / "audit.jsonl")

    result = resolve_integrity_status("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "signature_missing"
    assert result.manifest_path == str(integrity_manifest_paths(tmp_path).canonical_manifest)
    assert "release_manifest.json" not in result.manifest_path


def test_status_resolver_release_uses_same_canonical_manifest(tmp_path: Path) -> None:
    _write_project(tmp_path)

    result = resolve_integrity_status("pre_release", root=tmp_path)

    assert result.trust_state in {"manifest_missing", "manifest_path_divergence"}
    assert result.manifest_path == str(integrity_manifest_paths(tmp_path).canonical_manifest)


def test_status_resolver_does_not_use_yubikey_bundle_as_required_trust(tmp_path: Path) -> None:
    _write_project(tmp_path)
    paths = integrity_manifest_paths(tmp_path)
    rehash_manifest(tmp_path, author="A", reason="R", policy="dev", build_id="build-1", audit_log=tmp_path / "audit.jsonl")
    try:
        private_1, public_1 = generate_keypair(tmp_path / "key1.pem", tmp_path / "key1.pub")
        private_2, public_2 = generate_keypair(tmp_path / "key2.pem", tmp_path / "key2.pub")
    except SigningError as exc:
        pytest.skip(f"openssl Ed25519 signing unavailable: {exc}")
    policy = TrustPolicy(
        enrolled_yubikeys=[
            EnrolledYubiKey(yubikey_id="yk1", label="Key 1", owner_developer_id="liquidsky", public_key_pem=public_1.read_text(encoding="utf-8"), certificate_fingerprint_sha256="fp1"),
            EnrolledYubiKey(yubikey_id="yk2", label="Key 2", owner_developer_id="liquidsky", public_key_pem=public_2.read_text(encoding="utf-8"), certificate_fingerprint_sha256="fp2"),
        ],
        created_at="2026-07-08T00:00:00Z",
        updated_at="2026-07-08T00:00:00Z",
    )
    write_trust_policy(policy, tmp_path)
    manifest_sha = calculate_file_sha256(paths.canonical_manifest)
    payload = signed_payload(
        manifest_sha256=manifest_sha,
        build_id="build-1",
        git_commit="",
        app_version="1.0b",
        policy_mode="dev",
        project_name=policy.project_name,
    )
    phash = payload_hash(payload)
    bundle = SignatureBundle(
        signature_bundle_version="1",
        manifest_path=str(paths.canonical_manifest),
        manifest_sha256=manifest_sha,
        build_id="build-1",
        git_commit="",
        app_version="1.0b",
        signed_at="2026-07-08T00:00:00Z",
        signing_policy="dev",
        required_quorum=policy.required_signature_quorum,
        signatures=[
            SignatureEntry("sig1", "yk1", "liquidsky", "Key 1", "fp1", "9c", "ed25519", __import__("base64").b64encode(sign_bytes(canonical_json_bytes(payload), private_1.read_bytes())).decode("ascii"), phash, "2026-07-08T00:00:00Z"),
            SignatureEntry("sig2", "yk2", "liquidsky", "Key 2", "fp2", "9c", "ed25519", __import__("base64").b64encode(sign_bytes(canonical_json_bytes(payload), private_2.read_bytes())).decode("ascii"), phash, "2026-07-08T00:00:00Z"),
        ],
    )
    write_signature_bundle(bundle, paths.canonical_signature_bundle)

    result = resolve_integrity_status("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "signature_invalid"
    assert result.quorum_status == "not_required"


def test_status_resolver_legacy_only_is_path_divergence(tmp_path: Path) -> None:
    _write_project(tmp_path)
    legacy = tmp_path / "mac_audit_agent" / "security" / "integrity_manifest.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")

    result = resolve_integrity_status("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "manifest_path_divergence"
    assert result.legacy_manifest_detected is True


def test_exclusion_entries_include_policy_metadata() -> None:
    entries = default_exclusion_entries()
    assert entries
    assert all(entry.get("applies_to_policy") for entry in entries)
    assert any(entry["pattern"] == "docs/PRE_UAT_*_AUDIT.md" for entry in entries)
    assert any(entry["pattern"] == "macos_security_audit_agent.egg-info/" for entry in entries)


def test_wrapper_policy_defaults_to_public_release_when_frozen(monkeypatch) -> None:
    monkeypatch.delenv("MSAA_INTEGRITY_POLICY", raising=False)
    monkeypatch.delenv("MSAA_RELEASE_POLICY", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    assert default_wrapper_policy() == "public_release"


def test_wrapper_policy_defaults_to_public_release_for_consumer_parity(monkeypatch) -> None:
    monkeypatch.delenv("MSAA_INTEGRITY_POLICY", raising=False)
    monkeypatch.delenv("MSAA_RELEASE_POLICY", raising=False)
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert default_wrapper_policy() == "public_release"


def test_integrity_status_cli_is_headless_safe(tmp_path: Path) -> None:
    _write_project(tmp_path)
    script = (
        "import sys;"
        "import mac_audit_agent.integrity.__main__ as m;"
        "raise SystemExit(m.main(['status','--root',sys.argv[1],'--verbose']))"
    )
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], text=True, capture_output=True, check=False)

    assert result.returncode == 0
    assert "canonical manifest path:" in result.stdout
    assert "PySide6" not in result.stderr


def test_integrity_discover_cli_lists_legacy_manifest(tmp_path: Path) -> None:
    _write_project(tmp_path)
    legacy = tmp_path / "mac_audit_agent" / "security" / "integrity_manifest.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")

    result = subprocess.run([sys.executable, "-m", "mac_audit_agent.integrity", "discover", "--root", str(tmp_path)], text=True, capture_output=True, check=False)

    assert result.returncode in {0, 1}
    assert "recommended action:" in result.stdout
    assert str(legacy) in result.stdout


def test_sign_rejects_legacy_yubikey_quorum_flag(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mac_audit_agent.integrity",
            "sign",
            "--root",
            str(tmp_path),
            "--policy",
            "dev",
            "--author",
            "Liquidsky",
            "--reason",
            "approved development baseline",
            "--build-id",
            "build-1",
            "--require-yubikey-quorum",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "YubiKey quorum signing is optional legacy support" in result.stderr


def test_yubikey_verify_fails_closed_without_enrolled_keys(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run([sys.executable, "-m", "mac_audit_agent.integrity", "yubikey", "verify", "--root", str(tmp_path)], text=True, capture_output=True, check=False)

    assert result.returncode == 1
    assert "quorum: missing" in result.stdout
