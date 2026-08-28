from __future__ import annotations

import os
from pathlib import Path

import pytest

from mac_audit_agent.runtime.app_paths import RuntimePathError, get_ai_summary_path, get_generated_report_directory, get_user_data_directory


def test_default_macos_user_report_path_is_application_support() -> None:
    home = Path("/Users/test-user")
    assert get_user_data_directory(environ={}, home=home) == home / "Library/Application Support/MacAuditAgent"
    assert get_generated_report_directory(environ={}, home=home) == home / "Library/Application Support/MacAuditAgent/reports"
    assert get_ai_summary_path(environ={}, home=home).name == "ai_summary.json"


def test_absolute_report_override_has_precedence(tmp_path: Path) -> None:
    destination = tmp_path / "reports"
    assert get_generated_report_directory(environ={"MSAA_REPORT_DIR": str(destination)}, home=Path("/Users/ignored")) == destination


@pytest.mark.parametrize("value", ["relative/reports", "", "   ", "/", "/tmp/reports", "/System/reports", "/Library/reports", "/var/reports"])
def test_invalid_or_unsafe_report_override_is_rejected(value: str) -> None:
    with pytest.raises(RuntimePathError) as raised: get_generated_report_directory(environ={"MSAA_REPORT_DIR": value}, home=Path("/Users/test"))
    assert raised.value.code == "REPORT_PATH_INVALID"


def test_user_data_override_is_used_when_report_override_absent(tmp_path: Path) -> None:
    assert get_generated_report_directory(environ={"MSAA_USER_DATA_DIR": str(tmp_path / "data")}) == tmp_path / "data/reports"


def test_production_path_module_contains_no_developer_username() -> None:
    source = (Path(__file__).parents[1] / "mac_audit_agent/runtime/app_paths.py").read_text(encoding="utf-8")
    assert "liquidsky" not in source.lower()


def test_doctor_reports_persistence_without_writing_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "doctor-reports"))
    from mac_audit_agent.runtime.doctor import build_doctor_report

    payload = build_doctor_report()
    status = payload["report_persistence"]
    assert status["report_directory"] == str(tmp_path / "doctor-reports")
    assert status["report_directory_exists"] is True
    assert status["report_directory_writable"] is True
    assert status["current_uid"] == os.geteuid()
    assert status["ai_summary_persistence_available"] is True
    assert not (tmp_path / "doctor-reports" / "ai_summary.json").exists()
