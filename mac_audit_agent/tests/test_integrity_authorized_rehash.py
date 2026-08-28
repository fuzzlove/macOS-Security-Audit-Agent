from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mac_audit_agent.integrity.dev_manifest import (
    build_manifest,
    canonical_json_bytes,
    is_excluded_integrity_path,
    rehash_manifest,
    verify_manifest,
)
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signing import SigningError, generate_keypair, sign_manifest


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (package / "rules.json").write_text('{"severity": "high"}\n', encoding="utf-8")
    (package / "__pycache__").mkdir()
    (package / "__pycache__" / "app.cpython.pyc").write_bytes(b"volatile")
    (root / "reports").mkdir()
    (root / "reports" / "report.json").write_text("{}", encoding="utf-8")
    (root / "runtime.sqlite").write_text("not protected", encoding="utf-8")


def _rehash(root: Path, **kwargs):
    return rehash_manifest(
        root,
        author="Liquidsky Network Security",
        reason="authorized source update",
        developer_mode=True,
        audit_log=root / "audit.jsonl",
        **kwargs,
    )


def test_manifest_generation_and_verification_success(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, diff = _rehash(tmp_path)

    assert manifest.exists()
    assert manifest == integrity_manifest_paths(tmp_path).source_development_manifest
    assert diff["added"]
    result = verify_manifest(tmp_path, manifest_path=manifest)
    assert result.ok
    assert result.protected_files_verified >= 3
    assert result.unsigned_manifest_warning is True


def test_modified_file_detection_does_not_auto_rehash(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = _rehash(tmp_path)
    before = manifest.stat().st_mtime_ns
    time.sleep(0.01)

    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('tampered')\n", encoding="utf-8")
    result = verify_manifest(tmp_path, manifest_path=manifest)

    assert not result.ok
    assert result.modified_files[0].relative_path == "mac_audit_agent/app.py"
    assert manifest.stat().st_mtime_ns == before


def test_deleted_file_detection(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = _rehash(tmp_path)

    (tmp_path / "mac_audit_agent" / "rules.json").unlink()
    result = verify_manifest(tmp_path, manifest_path=manifest)

    assert not result.ok
    assert any(item.relative_path == "mac_audit_agent/rules.json" for item in result.missing_files)


def test_unexpected_file_detection(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = _rehash(tmp_path)

    (tmp_path / "mac_audit_agent" / "new_scanner.py").write_text("ENABLED = True\n", encoding="utf-8")
    result = verify_manifest(tmp_path, manifest_path=manifest)

    assert not result.ok
    assert any(item.relative_path == "mac_audit_agent/new_scanner.py" for item in result.unexpected_files)


def test_canonical_json_stability(tmp_path: Path) -> None:
    _write_project(tmp_path)
    left = build_manifest(tmp_path, author="A", reason="R")
    right = dict(reversed(list(left.items())))
    assert canonical_json_bytes(left) == canonical_json_bytes(right)


def test_unsigned_manifest_warns_and_require_signature_fails(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = _rehash(tmp_path)

    warning = verify_manifest(tmp_path, manifest_path=manifest)
    failure = verify_manifest(tmp_path, manifest_path=manifest, require_signature=True)

    assert warning.unsigned_manifest_warning is True
    assert not failure.ok
    assert failure.signature_errors


def test_signature_verification_success_and_failure(tmp_path: Path) -> None:
    _write_project(tmp_path)
    manifest, _ = _rehash(tmp_path)
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    try:
        generate_keypair(private_key, public_key)
    except SigningError as exc:
        pytest.skip(f"openssl Ed25519 signing unavailable: {exc}")

    signature = sign_manifest(manifest, private_key=private_key.read_bytes(), signature_path=tmp_path / "integrity_manifest.json.sig")
    ok = verify_manifest(tmp_path, manifest_path=manifest, signature_path=signature, public_key_path=public_key, require_signature=True)
    assert ok.ok
    assert ok.manifest_signature_valid is True

    signature.write_text("not-a-valid-signature\n", encoding="utf-8")
    bad_signature = verify_manifest(tmp_path, manifest_path=manifest, signature_path=signature, public_key_path=public_key, require_signature=True)
    assert not bad_signature.ok
    assert bad_signature.manifest_signature_valid is False
    assert bad_signature.signature_errors

    sign_manifest(manifest, private_key=private_key.read_bytes(), signature_path=signature)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('changed')\n", encoding="utf-8")
    failed = verify_manifest(tmp_path, manifest_path=manifest, signature_path=signature, public_key_path=public_key, require_signature=True)
    assert not failed.ok
    assert failed.modified_files


def test_rehash_requires_author_reason_and_developer_mode(tmp_path: Path) -> None:
    _write_project(tmp_path)
    with pytest.raises(ValueError):
        rehash_manifest(tmp_path, author="", reason="authorized", developer_mode=True)
    with pytest.raises(ValueError):
        rehash_manifest(tmp_path, author="Liquidsky", reason="", developer_mode=True)
    with pytest.raises(PermissionError):
        rehash_manifest(tmp_path, author="Liquidsky", reason="authorized", developer_mode=False)


def test_excluded_paths_are_not_hashed(tmp_path: Path) -> None:
    _write_project(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "PRE_UAT_UI_CONTROL_AUDIT.md").write_text("generated\n", encoding="utf-8")
    (tmp_path / "macos_security_audit_agent.egg-info").mkdir()
    (tmp_path / "macos_security_audit_agent.egg-info" / "PKG-INFO").write_text("generated\n", encoding="utf-8")
    (tmp_path / ".tmp_pre_uat").mkdir()
    (tmp_path / ".tmp_pre_uat" / "release_audit.sqlite3").write_text("generated\n", encoding="utf-8")
    manifest = build_manifest(tmp_path, author="A", reason="R")
    paths = {entry["relative_path"] for entry in manifest["files"]}

    assert "mac_audit_agent/__pycache__/app.cpython.pyc" not in paths
    assert "reports/report.json" not in paths
    assert "runtime.sqlite" not in paths
    assert "docs/PRE_UAT_UI_CONTROL_AUDIT.md" not in paths
    assert "macos_security_audit_agent.egg-info/PKG-INFO" not in paths
    assert ".tmp_pre_uat/release_audit.sqlite3" not in paths
    assert is_excluded_integrity_path("mac_audit_agent/security/integrity_manifest.json")


def test_rehash_policy_selects_canonical_manifest(tmp_path: Path) -> None:
    _write_project(tmp_path)
    paths = integrity_manifest_paths(tmp_path)
    private_key, public_key = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")

    dev_manifest, _ = rehash_manifest(tmp_path, author="A", reason="R", policy="dev", audit_log=tmp_path / "audit.jsonl")
    assert dev_manifest == paths.source_development_manifest
    assert dev_manifest.exists()

    release_manifest, _ = rehash_manifest(
        tmp_path,
        author="A",
        reason="R",
        policy="pre_release",
        sign=True,
        private_key_path=private_key,
        public_key_path=public_key,
        audit_log=tmp_path / "audit.jsonl",
    )
    assert release_manifest == paths.release_manifest
    assert release_manifest.exists()


def test_rehash_rejects_explicit_legacy_manifest_path(tmp_path: Path) -> None:
    _write_project(tmp_path)
    legacy_manifest = tmp_path / "mac_audit_agent" / "security" / "integrity_manifest.json"
    legacy_manifest.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Legacy manifest path was updated"):
        rehash_manifest(
            tmp_path,
            author="A",
            reason="R",
            policy="dev",
            manifest_path=legacy_manifest,
            audit_log=tmp_path / "audit.jsonl",
        )


def test_cli_rejects_ambiguous_legacy_modes(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mac_audit_agent.integrity",
            "rehash",
            "--root",
            str(tmp_path),
            "--developer-mode",
            "--release-mode",
            "--author",
            "Liquidsky",
            "--reason",
            "release build",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Ambiguous integrity mode: --developer-mode and --release-mode were both provided. Use --policy dev, --policy pre_release, or --policy public_release." in result.stderr


def test_cli_rehash_reports_post_validation(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mac_audit_agent.integrity",
            "rehash",
            "--root",
            str(tmp_path),
            "--policy",
            "dev",
            "--author",
            "Liquidsky",
            "--reason",
            "development baseline",
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Post-Rehash Validation:" in result.stdout
    assert "pre_uat_compatible: true" in result.stdout
    assert "manifest_path_written:" in result.stdout
    assert "manifest_path_used_by_pre_uat:" in result.stdout


def test_cli_rehash_requires_author_and_reason(tmp_path: Path) -> None:
    _write_project(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "mac_audit_agent.integrity", "rehash", "--root", str(tmp_path), "--developer-mode"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "--author" in result.stderr or "author" in result.stderr.lower()
