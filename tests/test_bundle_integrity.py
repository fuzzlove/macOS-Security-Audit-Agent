from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.bundle_integrity import (
    verify_bundle_integrity,
    write_bundle_integrity_manifest,
)


def _contents(tmp_path: Path) -> Path:
    contents = tmp_path / "MSAA.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Frameworks").mkdir()
    (contents / "Resources").mkdir()
    (contents / "MacOS" / "MSAA").write_bytes(b"code-signature-owned executable")
    (contents / "Frameworks" / "library.dylib").write_bytes(b"native library")
    (contents / "Resources" / "policy.json").write_text('{"enabled":true}', encoding="utf-8")
    return contents


def test_bundle_hash_manifest_verifies_static_files_and_excludes_primary_executable(tmp_path: Path) -> None:
    contents = _contents(tmp_path)
    write_bundle_integrity_manifest(contents, build_id="universal-test")

    result = verify_bundle_integrity(contents, verify_code_signature=False)

    assert result.status == "verified"
    assert result.result_code == "VALID"
    assert result.build_id == "universal-test"
    assert result.checked_files == 2


def test_bundle_hash_manifest_detects_modified_missing_and_unexpected_files(tmp_path: Path) -> None:
    contents = _contents(tmp_path)
    write_bundle_integrity_manifest(contents)
    (contents / "Frameworks" / "library.dylib").write_bytes(b"changed")
    (contents / "Resources" / "policy.json").unlink()
    (contents / "Resources" / "injected.bin").write_bytes(b"unexpected")

    result = verify_bundle_integrity(contents, verify_code_signature=False)

    assert result.status == "failed"
    assert result.result_code == "HASH_MISMATCH"
    assert result.modified_files == ("Frameworks/library.dylib",)
    assert result.missing_files == ("Resources/policy.json",)
    assert result.unexpected_files == ("Resources/injected.bin",)


def test_bundle_hash_manifest_rejects_manifest_path_traversal(tmp_path: Path) -> None:
    contents = _contents(tmp_path)
    manifest = write_bundle_integrity_manifest(contents)
    text = manifest.read_text(encoding="utf-8").replace('"path":"Frameworks/library.dylib"', '"path":"../outside"')
    manifest.write_text(text, encoding="utf-8")

    result = verify_bundle_integrity(contents, verify_code_signature=False)

    assert result.result_code == "BUNDLE_MANIFEST_INVALID"


def test_frozen_gui_normalizes_resource_root_to_app_contents(tmp_path: Path, monkeypatch) -> None:
    from mac_audit_agent.integrity import bundle_integrity
    from mac_audit_agent.integrity import wrapper_adapter
    from mac_audit_agent.runtime import app_paths

    contents = _contents(tmp_path)
    write_bundle_integrity_manifest(contents)
    executable = contents / "MacOS" / "MSAA"
    monkeypatch.setattr(app_paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(app_paths.sys, "executable", str(executable))
    monkeypatch.setattr(wrapper_adapter.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bundle_integrity.sys, "executable", str(executable))
    monkeypatch.setattr(bundle_integrity, "_verify_code_signature", lambda _root: (True, "test signature valid"))

    assert app_paths.application_integrity_root() == contents
    status = wrapper_adapter.IntegrityWrapperAdapter(contents / "Resources").get_integrity_status_for_ui()
    assert status.status == "verified"
    assert status.result_code == "VALID"
    assert status.manifest_path == str(contents / "Resources" / "msaa_bundle_integrity.json")
