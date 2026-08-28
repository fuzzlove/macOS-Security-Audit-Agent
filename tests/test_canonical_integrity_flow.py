from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.integrity.canonical import canonical_payload_sha256, normalize_relative_path, signed_payload_from_manifest
from mac_audit_agent.integrity.dev_manifest import rehash_manifest
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.result_codes import IntegrityResultCode
from mac_audit_agent.integrity.signed_manifest_validator import validate_signed_manifest
from mac_audit_agent.integrity.signing import generate_keypair
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status
from mac_audit_agent.integrity.ui_compat import get_integrity_health_model


def _write_project(root: Path) -> None:
    package = root / "mac_audit_agent"
    integrity = package / "integrity"
    trust = integrity / "trust"
    scripts = root / "scripts"
    trust.mkdir(parents=True)
    scripts.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("print('trusted')\n", encoding="utf-8")
    (integrity / "__init__.py").write_text("", encoding="utf-8")
    (scripts / "tool.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (root / "requirements.txt").write_text("", encoding="utf-8")
    (root / "README.md").write_text("# fixture\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# security\n", encoding="utf-8")


def _git_clean(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, text=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True, text=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "initial"],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )


def _sign_release(root: Path, *, require_clean_git: bool = True) -> tuple[Path, Path]:
    paths = integrity_manifest_paths(root)
    private_key = root.parent / f"{root.name}-private.pem"
    generate_keypair(private_key, paths.canonical_manifest.parent / "trust" / "msaa_release_ed25519_public.pem")
    if require_clean_git:
        subprocess.run(["git", "add", "mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem"], cwd=root, check=True, text=True, capture_output=True)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "add release public key"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        )
    manifest, _ = rehash_manifest(
        root,
        policy="public_release",
        release_mode=True,
        require_clean_git=require_clean_git,
        sign=True,
        private_key_path=private_key,
        public_key_path=paths.canonical_manifest.parent / "trust" / "msaa_release_ed25519_public.pem",
        author="Liquidsky Network Security",
        reason="release build",
        build_id="abc1234",
        release_id="msaa-20260709-abc1234",
    )
    return manifest, paths.canonical_signature_bundle


def test_valid_signed_manifest_passes_and_cli_gui_model_match(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    manifest, signature = _sign_release(tmp_path)

    result = validate_signed_manifest("public_release", root=tmp_path)
    model = get_integrity_health_model("public_release", root=tmp_path)

    assert result.status == "verified"
    assert result.result_code == IntegrityResultCode.VALID.value
    assert result.release_id == "msaa-20260709-abc1234"
    assert result.build_id == "abc1234"
    assert result.git_commit
    assert result.signing_key_fingerprint
    assert result.signature_valid is True
    assert model["status"] == result.status
    assert model["trust_state"] == result.trust_state
    assert model["result_code"] == result.result_code
    assert Path(result.canonical_manifest_path) == manifest
    assert Path(result.signature_path) == signature


def test_modified_deleted_and_added_source_files_fail(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    _sign_release(tmp_path, require_clean_git=False)

    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('tampered')\n", encoding="utf-8")
    modified = validate_signed_manifest("public_release", root=tmp_path)
    assert modified.trust_state == "source_files_modified"
    assert modified.result_code == IntegrityResultCode.HASH_MISMATCH.value
    assert "mac_audit_agent/app.py" in modified.source_modified_files

    (tmp_path / "mac_audit_agent" / "app.py").write_text("print('trusted')\n", encoding="utf-8")
    (tmp_path / "scripts" / "tool.sh").unlink()
    deleted = validate_signed_manifest("public_release", root=tmp_path)
    assert deleted.result_code == IntegrityResultCode.FILE_MISSING.value
    assert "scripts/tool.sh" in deleted.missing_files

    (tmp_path / "scripts" / "tool.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (tmp_path / "mac_audit_agent" / "unexpected.py").write_text("print('new')\n", encoding="utf-8")
    added = validate_signed_manifest("public_release", root=tmp_path)
    assert added.result_code == IntegrityResultCode.UNEXPECTED_FILE.value
    assert "mac_audit_agent/unexpected.py" in added.extra_files


def test_manifest_or_signature_mutation_fails(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    manifest, signature = _sign_release(tmp_path)

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    original_hash = canonical_payload_sha256(payload)
    payload["metadata"]["display_only"] = "mutable"
    assert canonical_payload_sha256(payload) == original_hash
    manifest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    assert validate_signed_manifest("public_release", root=tmp_path).status == "verified"

    payload["payload"]["reason"] = "tampered after signing"
    manifest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    tampered_manifest = validate_signed_manifest("public_release", root=tmp_path)
    assert tampered_manifest.trust_state == "manifest_modified_after_signing"
    assert tampered_manifest.result_code == IntegrityResultCode.SIGNATURE_INVALID.value

    _sign_release(tmp_path, require_clean_git=False)
    bundle = json.loads(signature.read_text(encoding="utf-8"))
    bundle["signature_base64"] = "AAAA"
    signature.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    tampered_signature = validate_signed_manifest("public_release", root=tmp_path)
    assert tampered_signature.trust_state == "signature_invalid"
    assert tampered_signature.result_code == IntegrityResultCode.SIGNATURE_INVALID.value


def test_unsigned_manifest_fails_release_mode(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    manifest, signature = _sign_release(tmp_path)
    signature.unlink()

    result = validate_signed_manifest("public_release", root=tmp_path)

    assert manifest.exists()
    assert result.trust_state == "signature_missing"
    assert result.status == "failed"
    assert result.result_code == IntegrityResultCode.MANIFEST_UNSIGNED.value


def test_missing_public_key_and_manifest_have_specific_result_codes(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    _sign_release(tmp_path)
    public_key = integrity_manifest_paths(tmp_path).canonical_manifest.parent / "trust" / "msaa_release_ed25519_public.pem"
    public_key.unlink()

    missing_key = validate_signed_manifest("public_release", root=tmp_path)
    assert missing_key.result_code == IntegrityResultCode.PUBLIC_KEY_MISSING.value

    manifest = integrity_manifest_paths(tmp_path).canonical_manifest
    manifest.unlink()
    missing_manifest = validate_signed_manifest("public_release", root=tmp_path)
    assert missing_manifest.result_code == IntegrityResultCode.MANIFEST_MISSING.value


def test_runtime_resolver_exception_maps_to_internal_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(policy: str = "dev", *, root: Path | None = None) -> object:
        raise RuntimeError("synthetic verifier failure")

    monkeypatch.setattr("mac_audit_agent.integrity.status_resolver.validate_signed_manifest", boom)

    result = resolve_integrity_status("public_release", root=tmp_path)

    assert result.status == "error"
    assert result.result_code == IntegrityResultCode.INTERNAL_ERROR.value
    assert result.trust_state == "verification_error"
    assert "RuntimeError" in result.reason


def test_dirty_git_refusal_lists_dirty_files(tmp_path: Path) -> None:
    _write_project(tmp_path)
    _git_clean(tmp_path)
    (tmp_path / "mac_audit_agent" / "app.py").write_text("dirty\n", encoding="utf-8")
    private_key = tmp_path / "private.pem"
    public_key = integrity_manifest_paths(tmp_path).canonical_manifest.parent / "trust" / "msaa_release_ed25519_public.pem"
    generate_keypair(private_key, public_key)

    with pytest.raises(RuntimeError) as excinfo:
        rehash_manifest(
            tmp_path,
            policy="public_release",
            release_mode=True,
            require_clean_git=True,
            sign=True,
            private_key_path=private_key,
            public_key_path=public_key,
            author="Liquidsky Network Security",
            reason="release build",
        )

    message = str(excinfo.value)
    assert "refusing to rehash dirty source tree" in message
    assert "mac_audit_agent/app.py" in message


def test_path_normalization_rejects_machine_specific_paths() -> None:
    assert normalize_relative_path("./mac_audit_agent/app.py") == "mac_audit_agent/app.py"
    with pytest.raises(ValueError):
        normalize_relative_path("/tmp/mac_audit_agent/app.py")
    with pytest.raises(ValueError):
        normalize_relative_path("../mac_audit_agent/app.py")


def test_signed_payload_excludes_signature_metadata(tmp_path: Path) -> None:
    manifest = {
        "payload": {"manifest_schema_version": "2", "hash_algorithm": "sha256", "files": []},
        "metadata": {"signed_at": "mutable"},
        "signature": "mutable",
        "public_key": "mutable",
    }
    payload = signed_payload_from_manifest(manifest)
    assert "signature" not in payload
    assert "public_key" not in payload
