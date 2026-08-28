from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key, sign_canonical_manifest
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.signed_manifest_validator import validate_signed_manifest


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='msaa-test'\n", encoding="utf-8")


def _enroll(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    create_developer_machine_key(tmp_path, developer="Dev", organization="Org", machine_label="Mac")


def test_signed_manifest_missing_signature_is_classified(tmp_path: Path) -> None:
    _write_project(tmp_path)
    rehash_manifest(tmp_path, author="Dev", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")

    result = validate_signed_manifest("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "signature_missing"
    assert result.can_auto_repair is True


def test_signed_manifest_modified_after_signing_is_classified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="Dev", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="Dev", reason="baseline", build_id="build-1")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["reason"] = "tampered after signing"
    manifest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    result = validate_signed_manifest("dev", root=tmp_path)

    assert result.status == "failed"
    assert result.trust_state == "manifest_modified_after_signing"
    assert result.requires_developer_approval is True


def test_signed_manifest_valid_developer_machine_signature_is_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="Dev", reason="baseline", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="Dev", reason="baseline", build_id="build-1")

    result = validate_signed_manifest("dev", root=tmp_path)

    assert result.status == "verified"
    assert result.trust_state == "trusted_developer_machine_signed_manifest"
    assert result.signature_valid is True
