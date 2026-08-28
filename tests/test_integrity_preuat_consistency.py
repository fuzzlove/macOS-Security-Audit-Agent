from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.evidence_freshness import utc_now_iso, verify_evidence_freshness
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.ui_compat import verify_integrity_health_model_matches_cli


def _project(root: Path) -> None:
    package = root / "mac_audit_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")


def test_preflight_reports_path_and_headless_consistency(tmp_path: Path) -> None:
    _project(tmp_path)

    result = run_integrity_preflight("dev", root=tmp_path, strict=True)

    assert result.status == "pass"
    assert result.headless_safe is True
    assert result.pre_uat_verifier_match is True
    assert result.release_verifier_match is True


def test_gui_adapter_uses_same_cli_status_model(tmp_path: Path) -> None:
    _project(tmp_path)

    comparison = verify_integrity_health_model_matches_cli("dev", root=tmp_path)

    assert comparison["status"] == "verified"
    assert comparison["mismatches"] == []


def test_stale_evidence_is_not_current_pass() -> None:
    now = utc_now_iso()
    stale = "2000-01-01T00:00:00Z"

    result = verify_evidence_freshness(last_verified_at=stale, command_started_at=now)

    assert result.status == "failed"
    assert "predates" in result.reason
