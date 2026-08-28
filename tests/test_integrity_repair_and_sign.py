from __future__ import annotations

from pathlib import Path

import pytest

from mac_audit_agent.integrity.developer_machine_signing import create_developer_machine_key
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status


def _project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")


def _enroll(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mac_audit_agent.integrity import developer_machine_signing

    monkeypatch.setattr(developer_machine_signing, "developer_key_dir", lambda: root.parent / f"{root.name}-keys")
    create_developer_machine_key(root, developer="Liquidsky Network Security", organization="Liquidsky Network Security", machine_label="Test Dev Mac")


def test_repair_and_sign_runs_post_sign_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    _enroll(tmp_path, monkeypatch)

    result = repair_and_sign_integrity(
        tmp_path,
        policy="dev",
        author="Liquidsky Network Security",
        reason="approved development baseline",
        build_id="build-1",
        developer_machine=True,
    )

    status = resolve_integrity_status("dev", root=tmp_path)
    assert result.status == "verified"
    assert status.result_code == "VALID"
    assert result.integrity_unknown is False


def test_source_change_requires_typed_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    _enroll(tmp_path, monkeypatch)
    repair_and_sign_integrity(tmp_path, policy="dev", author="A", reason="R", build_id="b1", developer_machine=True)
    (tmp_path / "mac_audit_agent/app.py").write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(Exception, match="APPROVE SOURCE BASELINE"):
        repair_and_sign_integrity(
            tmp_path,
            policy="dev",
            author="A",
            reason="R",
            build_id="b2",
            developer_machine=True,
            approve_current_source=True,
        )
