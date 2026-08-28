from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key, sign_canonical_manifest
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity


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

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: tmp_path.parent / f"{tmp_path.name}-keys")
    create_developer_machine_key(tmp_path, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def test_repair_and_sign_creates_requested_evidence_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)

    result = repair_and_sign_integrity(
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
    assert Path(result.evidence_path).name.startswith("integrity_repair_and_sign_")
    assert result.integrity_unknown is False


def test_repair_and_sign_blocks_source_change_without_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    manifest, _ = rehash_manifest(tmp_path, author="A", reason="R", developer_mode=True, audit_log=tmp_path / "audit.jsonl")
    sign_canonical_manifest(tmp_path, manifest_path=manifest, policy="dev", author="A", reason="R", build_id="build-1")
    (tmp_path / "mac_audit_agent" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = repair_and_sign_integrity(
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


def test_repair_and_sign_cli_is_headless_safe(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mac_audit_agent.integrity",
            "repair-and-sign",
            "--root",
            str(tmp_path),
            "--policy",
            "dev",
            "--author",
            "Liquidsky Network Security",
            "--reason",
            "approved development baseline",
            "--developer-machine",
            "--dry-run",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode in {1, 2}
    assert "PySide6" not in result.stderr
    assert "QApplication" not in result.stderr
