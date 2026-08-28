from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key
from mac_audit_agent.integrity.policy_resolver import resolve_integrity_policy
from mac_audit_agent.integrity.public_release_gate import run_public_release_gate


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='msaa-test'\nversion='0.0.1'\n", encoding="utf-8")
    (root / "dist").mkdir()
    (root / "dist" / "msaa_test-0.0.1-py3-none-any.whl").write_bytes(b"not a real wheel")


def _enroll(root: Path, key_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: key_root)
    create_developer_machine_key(root, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def test_policy_resolver_dev_uses_source_manifest_only(tmp_path: Path) -> None:
    resolved = resolve_integrity_policy("dev", root=tmp_path)

    assert resolved.policy == "dev"
    assert resolved.validate_source_manifest is True
    assert resolved.validate_artifacts is False
    assert resolved.source_manifest_path.endswith("mac_audit_agent/integrity/integrity_manifest.json")
    assert "release_manifest.json" not in resolved.source_manifest_path


def test_policy_resolver_public_release_requires_artifacts(tmp_path: Path) -> None:
    resolved = resolve_integrity_policy("public_release", root=tmp_path)

    assert resolved.policy == "public_release"
    assert resolved.validate_source_manifest is True
    assert resolved.validate_artifacts is True
    assert resolved.artifact_manifest_path.endswith("dist/MSAA_RELEASE_ARTIFACTS.json")
    assert resolved.require_pytest_evidence is True
    assert resolved.require_clean_install_evidence is True


def test_public_release_gate_blocks_when_source_cannot_be_signed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    monkeypatch.setattr("mac_audit_agent.integrity.public_release_gate._write_evidence", lambda result, started_at: tmp_path / "evidence.json")

    result = run_public_release_gate(
        tmp_path,
        author="Liquidsky Network Security",
        reason="public release gate",
        build_id="build-1",
        developer_machine=True,
        sign_artifacts=True,
    )

    assert result.release_ready_for_public_distribution is False
    assert "source_integrity_not_trusted" in result.blocking_checks
    assert result.source_signature_status == "developer_machine_not_enrolled"


def test_public_release_gate_signs_artifacts_but_does_not_mark_partial_run_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_project(tmp_path)
    _enroll(tmp_path, tmp_path.parent / f"{tmp_path.name}-keys", monkeypatch)
    monkeypatch.setattr("mac_audit_agent.integrity.public_release_gate._write_evidence", lambda result, started_at: tmp_path / "evidence.json")

    result = run_public_release_gate(
        tmp_path,
        author="Liquidsky Network Security",
        reason="public release gate",
        build_id="build-1",
        developer_machine=True,
        sign_artifacts=True,
    )

    assert result.source_integrity_status == "verified"
    assert result.artifact_integrity_status == "verified"
    assert result.release_ready_for_public_distribution is False
    assert "pytest_not_run" in result.blocking_checks
    assert "clean_install_not_run" in result.blocking_checks
    assert Path(result.artifact_manifest_path).exists()
    assert Path(result.artifact_signature_path).exists()


def test_public_release_gate_import_is_headless_safe() -> None:
    script = """
import importlib, json, sys
importlib.import_module('mac_audit_agent.integrity.public_release_gate')
print(json.dumps(sorted(m for m in sys.modules if m.split('.', 1)[0] in {'PySide6', 'PyQt6', 'PyQt5', 'AppKit', 'Cocoa'})))
"""
    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False, timeout=20)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"
