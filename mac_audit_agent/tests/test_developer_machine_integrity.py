from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines, revoke_developer_machine
from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key, sign_canonical_manifest
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("generated\n", encoding="utf-8")
    (root / "macos_security_audit_agent.egg-info").mkdir()
    (root / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("generated\n", encoding="utf-8")


def test_developer_machine_enroll_sign_and_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    _write_project(tmp_path)
    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    identity = create_developer_machine_key(
        tmp_path,
        developer="Liquidsky Network Security",
        organization="Liquidsky Network Security",
        machine_label="Test Dev Mac",
    )
    manifest, _ = rehash_manifest(tmp_path, author="Liquidsky Network Security", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    signature = sign_canonical_manifest(
        tmp_path,
        manifest_path=manifest,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved development baseline",
        build_id="test-build",
    )
    result = resolve_integrity_status("dev", root=tmp_path)

    assert manifest == integrity_manifest_paths(tmp_path).canonical_manifest
    assert signature == integrity_manifest_paths(tmp_path).canonical_signature_bundle
    assert result.status == "verified"
    assert result.trust_state == "trusted_developer_machine_signed_manifest"
    assert result.signature_valid is True
    assert result.signer_status[0]["developer_machine_id"] == identity.developer_machine_id


def test_registry_does_not_store_raw_machine_identifiers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    _write_project(tmp_path)
    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    create_developer_machine_key(tmp_path, developer="Dev", organization="Org", machine_label="Mac")
    payload = json.loads(integrity_manifest_paths(tmp_path).canonical_trusted_developer_machines.read_text(encoding="utf-8"))
    text = json.dumps(payload)

    assert "IOPlatformUUID" not in text
    assert "IOPlatformSerialNumber" not in text
    assert payload["trusted_machines"][0]["hardware_uuid_hash"]
    assert payload["trusted_machines"][0]["public_key_fingerprint_sha256"]


def test_revoked_machine_signature_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    _write_project(tmp_path)
    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    identity = create_developer_machine_key(tmp_path, developer="Dev", organization="Org", machine_label="Mac")
    manifest, _ = rehash_manifest(tmp_path, author="Dev", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="Dev", reason="baseline", build_id="test")
    revoke_developer_machine(tmp_path, identity.developer_machine_id, "test revoke")

    result = resolve_integrity_status("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "developer_machine_revoked"


def test_generated_artifacts_are_excluded_from_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    _write_project(tmp_path)
    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    create_developer_machine_key(tmp_path, developer="Dev", organization="Org", machine_label="Mac")
    manifest, _ = rehash_manifest(tmp_path, author="Dev", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="Dev", reason="baseline", build_id="test")
    (tmp_path / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("changed generated\n", encoding="utf-8")
    (tmp_path / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("changed generated\n", encoding="utf-8")

    result = resolve_integrity_status("dev", root=tmp_path)

    assert result.status == "verified"
    assert not result.modified_files
