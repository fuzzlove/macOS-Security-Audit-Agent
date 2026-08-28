from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import stat

import pytest

from mac_audit_agent.data_governance import AccessContext, DataGovernanceService, GovernanceError, ProtectionEvidence, Role, detect_sensitive_content, sanitize_for_processing


def context(role: Role = Role.ADMINISTRATOR) -> AccessContext:
    return AccessContext("analyst", role, True, "test authorization", (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())


def test_unclassified_data_fails_closed(tmp_path: Path) -> None:
    service = DataGovernanceService(tmp_path / "governance.db")
    with pytest.raises(GovernanceError, match="Unclassified"):
        service.authorize("view", "mystery_data", context())


def test_rbac_export_and_protection_are_fail_closed_and_audited(tmp_path: Path) -> None:
    service = DataGovernanceService(tmp_path / "governance.db")
    assert not service.authorize("view", "forensic_evidence", context(Role.VIEWER)).allowed
    assert not service.authorize("export", "forensic_evidence", context(), approval=False, destination="case.zip").allowed
    missing = service.authorize("export", "forensic_evidence", context(), approval=True, destination="case.zip")
    assert not missing.allowed and "verified_encryption_at_rest" in missing.requirements
    allowed = service.authorize("export", "forensic_evidence", context(), approval=True, destination="case.zip", protection=ProtectionEvidence(encryption_at_rest_verified=True, key_management_reference="kms-case-1"))
    assert allowed.allowed
    assert service.verify_audit_chain()


def test_external_sharing_and_ai_are_prohibited_by_default(tmp_path: Path) -> None:
    service = DataGovernanceService(tmp_path / "governance.db")
    assert not service.authorize("share", "security_event", context(), approval=True, destination="community", protection=ProtectionEvidence(secure_transport_verified=True)).allowed
    decision, payload, findings = service.prepare_ai_input("forensic_evidence", {"note": "hello"}, context(), external=True, approval=True)
    assert not decision.allowed and payload is None and findings == []


def test_secret_detection_and_redaction_never_return_secret_value() -> None:
    value = {"password": "hunter2", "note": "Authorization: Bearer abcdefghijklmno", "path": "/Users/alice/case.txt"}
    findings = detect_sensitive_content(value)
    assert {item["type"] for item in findings} >= {"sensitive_field", "authorization"}
    sanitized, _ = sanitize_for_processing(value)
    rendered = str(sanitized)
    assert "hunter2" not in rendered and "abcdefghijklmno" not in rendered and "alice" not in rendered


def test_retention_is_a_plan_and_invalid_timestamps_are_preserved(tmp_path: Path) -> None:
    service = DataGovernanceService(tmp_path / "governance.db")
    now = datetime.now(timezone.utc)
    rows = [{"record_id": "old", "timestamp": (now - timedelta(days=91)).isoformat()}, {"record_id": "new", "timestamp": now.isoformat()}, {"record_id": "unknown", "timestamp": "invalid"}]
    assert service.retention_candidates("security_event", rows, now=now) == ["old"]


def test_privacy_impact_and_transparency_explain_policy(tmp_path: Path) -> None:
    service = DataGovernanceService(tmp_path / "governance.db")
    pia = service.privacy_impact_assessment("community export", ["security_event", "forensic_evidence"], external_transfer=True, personal_content=False)
    assert pia["assessment_status"] == "REVIEW_REQUIRED"
    assert pia["highest_classification"] == "RESTRICTED"
    report = service.transparency_report()
    evidence = next(item for item in report["data_types"] if item["data_type"] == "forensic_evidence")
    assert evidence["retention_days"] is None and evidence["encryption_at_rest_required"] is True


def test_database_permissions_and_retention_changes_require_admin_approval(tmp_path: Path) -> None:
    database = tmp_path / "governance.db"
    service = DataGovernanceService(database)
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert not service.set_retention("security_event", 30, context(Role.SECURITY_ANALYST), owner="security", approval=True).allowed
    assert service.set_retention("security_event", 30, context(), owner="security", approval=True).allowed
    assert service.verify_audit_chain()


def test_governance_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    target.touch()
    link = tmp_path / "governance.db"
    link.symlink_to(target)
    with pytest.raises(GovernanceError, match="symbolic"):
        DataGovernanceService(link)


def test_security_control_database_maps_data_governance() -> None:
    from mac_audit_agent.security_control_database import SecurityControlDatabase

    control = SecurityControlDatabase().get("data_governance")
    assert control is not None
    assert {"AC-3", "SC-28", "SI-12"}.issubset(control.nist_controls)
