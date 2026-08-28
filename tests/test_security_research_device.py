from pathlib import Path

from mac_audit_agent.security_research_device import PROFILES, evaluate_automatic_tasks, export_assessment, tasks_for_profile


class _Evidence:
    values = {"filevault_enabled": True, "secure_boot_verified": None, "sip_enabled": False, "firewall_enabled": True}
    observations = {key: {"state": value} for key, value in values.items()}
    collected_at = "2026-07-20T00:00:00+00:00"


def test_profiles_are_ordered_and_submission_profile_is_not_a_compliance_claim():
    assert [p.profile_id for p in PROFILES] == ["theft_prevention", "sensitive_research", "government_submission_readiness"]
    assert len(tasks_for_profile("theft_prevention")) < len(tasks_for_profile("sensitive_research")) < len(tasks_for_profile("government_submission_readiness"))
    assert "does not establish compliance" in PROFILES[-1].description.lower()


def test_automatic_checks_keep_missing_telemetry_unknown():
    result = evaluate_automatic_tasks(lambda: _Evidence())
    assert result["filevault"]["status"] == "pass"
    assert result["sip"]["status"] == "fail"
    assert result["secure_boot"]["status"] == "unknown"


def test_export_is_deterministic_in_structure_and_disclaims_certification(tmp_path: Path):
    target = export_assessment(tmp_path / "assessment.json", profile_id="theft_prevention", states={"filevault": {"status": "pass"}})
    text = target.read_text(encoding="utf-8")
    assert '"sha256"' in text
    assert "not certification" in text
    assert "FileVault" in text
