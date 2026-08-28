from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.path_consensus import verify_manifest_path_consensus
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.signature_roundtrip import validate_signature_roundtrip
from mac_audit_agent.integrity.signed_manifest_validator import validate_signed_manifest
from mac_audit_agent.integrity.ui_compat import get_integrity_health_model
from mac_audit_agent.quality.audit_models import FunctionalCheck
from mac_audit_agent.quality.evidence_consistency import normalize_check_status


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='msaa-test'\nversion='0.0.1'\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("generated\n", encoding="utf-8")
    egg = root / "macos_security_audit_agent.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text("generated\n", encoding="utf-8")


def _enroll(root: Path, key_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: key_root)
    create_developer_machine_key(root, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def _sign(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enroll(root, root.parent / f"{root.name}-keys", monkeypatch)
    result = repair_and_sign_integrity(
        root,
        policy="dev",
        author="Liquidsky Network Security",
        reason="test baseline",
        build_id="test-build",
        developer_machine=True,
        approve_current_source=True,
        typed_confirmation="APPROVE SOURCE BASELINE",
    )
    assert result.status == "verified"


def test_valid_signed_manifest_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    assert validate_signed_manifest("dev", root=tmp_path).trust_state == "trusted_developer_machine_signed_manifest"


def test_modifying_source_file_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert validate_signed_manifest("dev", root=tmp_path).trust_state == "source_files_modified"


def test_deleting_source_file_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    (tmp_path / "mac_audit_agent" / "app.py").unlink()
    result = validate_signed_manifest("dev", root=tmp_path)
    assert result.trust_state == "source_files_modified"
    assert "mac_audit_agent/app.py" in result.missing_files


def test_added_unexpected_source_file_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    (tmp_path / "mac_audit_agent" / "unexpected.py").write_text("VALUE = 99\n", encoding="utf-8")
    result = validate_signed_manifest("dev", root=tmp_path)
    assert result.trust_state == "source_files_modified"
    assert "mac_audit_agent/unexpected.py" in result.extra_files


def test_modifying_generated_files_does_not_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    (tmp_path / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("changed\n", encoding="utf-8")
    (tmp_path / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("changed\n", encoding="utf-8")
    assert validate_signed_manifest("dev", root=tmp_path).status == "verified"


def test_manifest_and_signature_tamper_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    manifest = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["reason"] = "tampered"
    manifest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    assert validate_signed_manifest("dev", root=tmp_path).trust_state == "manifest_modified_after_signing"


def test_signature_field_mutation_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    signature = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.signature.json"
    payload = json.loads(signature.read_text(encoding="utf-8"))
    payload["signature_base64"] = payload["signature_base64"][:-4] + "AAAA"
    signature.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    assert validate_signed_manifest("dev", root=tmp_path).trust_state == "signature_invalid"


def test_deleting_manifest_or_signature_classifies_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    signature = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.signature.json"
    signature.unlink()
    assert validate_signed_manifest("dev", root=tmp_path).trust_state == "signature_missing"
    manifest = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.json"
    manifest.unlink()
    assert validate_signed_manifest("dev", root=tmp_path).trust_state in {"manifest_missing", "manifest_path_divergence"}


def test_dev_policy_does_not_use_release_manifest(tmp_path: Path) -> None:
    result = verify_manifest_path_consensus("dev", root=tmp_path)
    assert result.consensus is True
    assert "release_manifest.json" not in result.cli_status_path


def test_pass_with_failed_evidence_is_normalized() -> None:
    check = FunctionalCheck("x", "Integrity", "x", "x", "blocker").passed("ok", {"status": "failed"})
    normalize_check_status(check)
    assert check.status == "BLOCKER"


def test_integrity_health_model_matches_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    validation = validate_signed_manifest("dev", root=tmp_path)
    model = get_integrity_health_model("dev", root=tmp_path)
    assert model["trust_state"] == validation.trust_state


def test_signature_roundtrip_rejects_tampered_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _sign(tmp_path, monkeypatch)
    manifest = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.json"
    signature = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.signature.json"
    result = validate_signature_roundtrip(tmp_path, manifest, signature)
    assert result.status == "verified"
    assert result.tampered_signature_rejected is True


def test_release_key_rehash_signs_json_bundle_and_verifies(tmp_path: Path) -> None:
    _write_project(tmp_path)
    private_key = tmp_path / "release_private.pem"
    public_key = tmp_path / "mac_audit_agent" / "integrity" / "trust" / "msaa_release_ed25519_public.pem"
    public_key.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
    rehash_manifest(
        tmp_path,
        author="Liquidsky Network Security",
        reason="release build",
        build_id="test-build",
        release_id="test-release",
        release_mode=True,
        sign=True,
        private_key_path=private_key,
        require_clean_git=False,
        policy="public_release",
    )
    signature = tmp_path / "mac_audit_agent" / "integrity" / "integrity_manifest.signature.json"
    bundle = json.loads(signature.read_text(encoding="utf-8"))
    assert bundle["signature_model"] == "trusted_release_key"
    assert bundle["signed_payload"] == "canonical_manifest_json_bytes"
    result = validate_signed_manifest("public_release", root=tmp_path)
    assert result.status == "verified"
    assert result.trust_state == "trusted_release_key_signed_manifest"


def test_dirty_git_tree_refuses_release_rehash(tmp_path: Path) -> None:
    _write_project(tmp_path)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "MSAA Test"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as exc:
        rehash_manifest(
            tmp_path,
            author="Liquidsky Network Security",
            reason="release build",
            release_mode=True,
            require_clean_git=True,
            policy="public_release",
        )
    assert "refusing to rehash dirty source tree" in str(exc.value)
    assert "mac_audit_agent/app.py" in str(exc.value)
