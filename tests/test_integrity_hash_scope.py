from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.dev_manifest import build_manifest
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report


def _project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")


def test_generated_egg_info_and_sqlite_are_excluded(tmp_path: Path) -> None:
    _project(tmp_path)
    egg = tmp_path / "macos_security_audit_agent.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text("generated\n", encoding="utf-8")
    (tmp_path / "release_audit.sqlite3").write_text("db", encoding="utf-8")

    report = build_hash_scope_report(tmp_path)

    assert "mac_audit_agent/app.py" in report.included_files
    assert "macos_security_audit_agent.egg-info/PKG-INFO" in report.excluded_files
    assert "release_audit.sqlite3" in report.excluded_files
    assert report.dangerous_unclassified_files == []


def test_manifest_and_signature_do_not_hash_themselves(tmp_path: Path) -> None:
    _project(tmp_path)
    manifest_path = tmp_path / "mac_audit_agent/integrity/integrity_manifest.json"
    signature_path = tmp_path / "mac_audit_agent/integrity/integrity_manifest.signature.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{}", encoding="utf-8")
    signature_path.write_text("{}", encoding="utf-8")

    manifest = build_manifest(tmp_path, author="A", reason="R")
    files = {item["relative_path"] for item in manifest["payload"]["files"]}

    assert "mac_audit_agent/integrity/integrity_manifest.json" not in files
    assert "mac_audit_agent/integrity/integrity_manifest.signature.json" not in files
    assert "dist/MSAA_RELEASE_ARTIFACTS.json" not in files
