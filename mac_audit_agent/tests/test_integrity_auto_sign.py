from __future__ import annotations

from pathlib import Path

import pytest

from mac_audit_agent.integrity.auto_sign import auto_sign_integrity
from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key, sign_canonical_manifest
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='msaa-test'\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("generated\n", encoding="utf-8")
    (root / "macos_security_audit_agent.egg-info").mkdir()
    (root / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("generated\n", encoding="utf-8")


def _enroll(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path / "keys")
    create_developer_machine_key(tmp_path, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def test_auto_sign_creates_manifest_signature_and_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)

    result = auto_sign_integrity(
        tmp_path,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved development baseline",
        build_id="build-1",
        developer_machine=True,
        verify_pre_uat_compatible=True,
    )

    assert result.status == "verified"
    assert result.trust_state == "trusted_developer_machine_signed_manifest"
    assert Path(result.canonical_manifest_path) == integrity_manifest_paths(tmp_path).canonical_manifest
    assert Path(result.signature_path) == integrity_manifest_paths(tmp_path).canonical_signature_bundle
    assert Path(result.evidence_path).exists()
    assert result.pre_uat_compatible is True
    assert result.integrity_unknown is False


def test_auto_sign_fails_clearly_when_developer_machine_missing(tmp_path: Path) -> None:
    _write_project(tmp_path)

    result = auto_sign_integrity(
        tmp_path,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved development baseline",
        build_id="build-1",
        developer_machine=True,
    )

    assert result.status == "failed"
    assert result.trust_state == "developer_machine_not_enrolled"
    assert result.integrity_unknown is False


def test_auto_sign_missing_private_key_does_not_rewrite_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="A", reason="original", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    original = manifest.read_bytes()
    from mac_audit_agent.integrity import developer_machine_signing

    developer_machine_signing._private_key_path(
        developer_machine_signing.get_developer_machine_identity(tmp_path).developer_machine_id
    ).unlink()

    result = auto_sign_integrity(
        tmp_path,
        policy="dev",
        author="A",
        reason="must not replace manifest",
        developer_machine=True,
    )

    assert result.status == "failed"
    assert result.trust_state == "developer_signing_key_missing"
    assert manifest.read_bytes() == original


def test_auto_sign_blocks_real_source_changes_without_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="A", reason="R", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="A", reason="R", build_id="build-1")
    (tmp_path / "mac_audit_agent" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = auto_sign_integrity(
        tmp_path,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved development baseline",
        build_id="build-2",
        developer_machine=True,
    )

    assert result.status == "failed"
    assert result.trust_state == "source_files_modified"
    assert result.requires_developer_approval is True
    assert "mac_audit_agent/app.py" in result.source_modified_files


def test_auto_sign_approves_real_source_changes_when_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="A", reason="R", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="A", reason="R", build_id="build-1")
    (tmp_path / "mac_audit_agent" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = auto_sign_integrity(
        tmp_path,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved source update",
        build_id="build-2",
        developer_machine=True,
        approve_current_source=True,
        typed_confirmation="APPROVE SOURCE BASELINE",
    )

    assert result.status == "verified"
    assert resolve_integrity_status("dev", root=tmp_path).trust_state == "trusted_developer_machine_signed_manifest"


def test_auto_sign_generated_artifact_drift_does_not_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    result = auto_sign_integrity(tmp_path, policy="dev", author="A", reason="R", build_id="build-1", developer_machine=True)
    assert result.status == "verified"

    (tmp_path / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("changed generated\n", encoding="utf-8")
    (tmp_path / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("changed generated\n", encoding="utf-8")
    again = auto_sign_integrity(tmp_path, policy="dev", author="A", reason="generated drift repair", build_id="build-2", developer_machine=True)

    assert again.status == "verified"
    assert again.source_modified_files == []


def test_auto_sign_cli_forwards_typed_confirmation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mac_audit_agent.integrity import __main__ as integrity_cli

    captured: dict[str, object] = {}

    class Result:
        status = "verified"
        integrity_unknown = False

        def to_dict(self) -> dict[str, str]:
            return {"status": self.status}

    monkeypatch.setattr(integrity_cli, "ensure_integrity_cli_headless_safe", lambda **kwargs: None)
    monkeypatch.setattr(integrity_cli, "auto_sign_integrity", lambda root, **kwargs: captured.update(kwargs) or Result())
    args = integrity_cli.build_parser().parse_args(
        [
            "auto-sign",
            "--root",
            str(tmp_path),
            "--author",
            "A",
            "--reason",
            "R",
            "--developer-machine",
            "--approve-current-source",
            "--typed-confirmation",
            "APPROVE SOURCE BASELINE",
            "--json",
        ]
    )

    assert integrity_cli.command_auto_sign(args) == 0
    assert captured["typed_confirmation"] == "APPROVE SOURCE BASELINE"
