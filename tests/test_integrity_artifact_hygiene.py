from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.artifact_hygiene import scan_artifact_hygiene


def test_artifact_hygiene_blocks_runtime_database_and_private_key(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "runtime.sqlite3").write_text("db", encoding="utf-8")
    (tmp_path / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")

    result = scan_artifact_hygiene(tmp_path)

    assert result.status == "failed"
    assert "dist/runtime.sqlite3" in result.offenders
    assert "private.pem" in result.offenders


def test_artifact_hygiene_allows_public_key_material(tmp_path: Path) -> None:
    public_key = tmp_path / "mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem"
    public_key.parent.mkdir(parents=True)
    public_key.write_text("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    result = scan_artifact_hygiene(tmp_path)

    assert result.status == "passed"
