from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.canonical import canonical_payload_bytes, canonical_payload_sha256
from mac_audit_agent.integrity.dev_manifest import build_manifest


def _project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")


def test_same_manifest_data_produces_same_canonical_bytes() -> None:
    a = {"payload": {"manifest_schema_version": "2", "hash_algorithm": "sha256", "files": [{"relative_path": "b.py", "sha256": "2"}]}}
    b = {"payload": {"files": [{"sha256": "2", "relative_path": "b.py"}], "hash_algorithm": "sha256", "manifest_schema_version": "2"}}

    assert canonical_payload_bytes(a) == canonical_payload_bytes(b)
    assert canonical_payload_sha256(a) == canonical_payload_sha256(b)


def test_transient_metadata_and_whitespace_do_not_affect_hash() -> None:
    manifest = {"payload": {"manifest_schema_version": "2", "hash_algorithm": "sha256", "files": []}, "metadata": {"verification_status": "failed"}}
    changed = {"metadata": {"verification_status": "verified", "signed_at": "later"}, "payload": manifest["payload"]}

    assert canonical_payload_sha256(manifest) == canonical_payload_sha256(changed)


def test_source_change_changes_manifest_hash_but_generated_change_does_not(tmp_path: Path) -> None:
    _project(tmp_path)
    generated = tmp_path / "macos_security_audit_agent.egg-info"
    generated.mkdir()
    (generated / "PKG-INFO").write_text("one\n", encoding="utf-8")

    first = build_manifest(tmp_path, author="A", reason="R")
    (generated / "PKG-INFO").write_text("two\n", encoding="utf-8")
    generated_changed = build_manifest(tmp_path, author="A", reason="R")
    assert canonical_payload_sha256(first) != ""
    assert [item["relative_path"] for item in first["payload"]["files"]] == [item["relative_path"] for item in generated_changed["payload"]["files"]]

    (tmp_path / "mac_audit_agent/app.py").write_text("VALUE = 2\n", encoding="utf-8")
    source_changed = build_manifest(tmp_path, author="A", reason="R")
    assert canonical_payload_sha256(first) != canonical_payload_sha256(source_changed)
