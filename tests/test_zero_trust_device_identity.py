from __future__ import annotations

import json

import pytest

from mac_audit_agent.continuous_security_assurance import ContinuousSecurityAssuranceEngine
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.zero_trust.device_identity import (
    CONDITIONAL, RESTRICTED, TRUSTED, UNTRUSTED, DeviceIdentityProfile,
    DeviceIdentityRepository, ZeroTrustDeviceIdentityEngine,
)


def evidence() -> dict:
    return {
        "identity_accounts_authorized": True, "authentication_anomalies": 0, "ssh_identity_changes": 0,
        "unapproved_applications": 0, "unsigned_applications": 0, "modified_trusted_applications": 0,
        "known_vulnerabilities": 0, "firewall_enabled": True, "filevault_enabled": True,
        "sip_enabled": True, "gatekeeper_enabled": True, "privacy_controls_compliant": True,
        "suspicious_persistence": 0, "ransomware_indicators": 0, "suspicious_network_activity": 0,
        "backup_healthy": True, "evidence_collection_ready": True, "response_workflow_ready": True,
        "evidence_references": {"identity_accounts_authorized": ["identity:snapshot-1"], "firewall_enabled": ["config:firewall-1"]},
    }


def profile(device_id: str = "device-1") -> DeviceIdentityProfile:
    return DeviceIdentityProfile.from_approved_metadata({
        "model": "MacBookPro", "architecture": "arm64", "hardware_capabilities": ["secure_boot", "secure_enclave"],
        "secure_enclave_available": True, "secure_boot_status": "verified", "macos_version": "15.5",
        "build_number": "24F74", "patch_status": "current",
        "evidence_reference": ["hardware:profile-1"],
    }, device_id=device_id)


def posture(values: dict, timestamp: str = "2026-07-17T10:00:00Z"):
    return ContinuousSecurityAssuranceEngine().evaluate(values, device_id="device-1", hostname="mac.test", timestamp=timestamp)[0]


def test_trusted_device_requires_complete_current_evidence() -> None:
    attestation, event = ZeroTrustDeviceIdentityEngine().verify(profile(), posture(evidence()))
    assert attestation.trust_state == TRUSTED
    assert attestation.identity_status == "VERIFIED"
    assert attestation.attestation_hash and ZeroTrustDeviceIdentityEngine.verify_attestation(attestation)
    assert event.previous_trust_state == "NOT PREVIOUSLY VERIFIED"
    assert attestation.qualification.startswith("Internal MSAA evidence representation")


def test_identifier_is_organization_scoped_and_raw_value_is_not_retained() -> None:
    raw_identifier = "C02-PRIVATE-SERIAL"
    first = DeviceIdentityProfile.from_approved_metadata({}, stable_identifier=raw_identifier, organization_salt=b"a" * 32)
    second = DeviceIdentityProfile.from_approved_metadata({}, stable_identifier=raw_identifier, organization_salt=b"b" * 32)
    assert first.device_id != second.device_id
    assert raw_identifier not in json.dumps(first.to_dict())
    with pytest.raises(ValueError, match="at least 16 bytes"):
        DeviceIdentityProfile.from_approved_metadata({}, stable_identifier=raw_identifier, organization_salt=b"short")


def test_device_and_posture_identity_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="do not match"):
        ZeroTrustDeviceIdentityEngine().verify(profile("wrong-device"), posture(evidence()))


@pytest.mark.parametrize("key", ["firewall_enabled", "filevault_enabled", "sip_enabled"])
def test_critical_configuration_regression_restricts_trust(key: str) -> None:
    values = evidence(); values[key] = {"value": False, "evidence_reference": [f"config:{key}"]}
    attestation, event = ZeroTrustDeviceIdentityEngine().verify(profile(), posture(values))
    assert attestation.trust_state == RESTRICTED
    assert f"config:{key}" in event.evidence_reference
    assert ZeroTrustDeviceIdentityEngine().emergency_response_context(attestation, event)["authorization_required"] is True


def test_unsigned_application_moves_device_to_conditional_trust() -> None:
    values = evidence(); values["unsigned_applications"] = {"value": 1, "evidence_reference": ["app:unsigned-1"]}
    attestation, event = ZeroTrustDeviceIdentityEngine().verify(profile(), posture(values))
    assert attestation.trust_state == CONDITIONAL
    assert "zt.review-unsigned-software" in event.policy_trigger
    assert any(item.recommended_action == "require_review" and item.matched for item in attestation.policy_results)


def test_critical_kev_and_persistence_have_evidence_based_impacts() -> None:
    values = evidence(); values["suspicious_persistence"] = {"value": 1, "evidence_reference": ["plist:agent-1"]}
    attestation, event = ZeroTrustDeviceIdentityEngine().verify(profile(), posture(values), context={"critical_kev_vulnerabilities": 1, "evidence_reference": ["vulnerability:kev-1"]})
    assert attestation.trust_state == RESTRICTED
    assert "zt.require-remediation-critical-kev" in event.policy_trigger
    assert "plist:agent-1" in event.evidence_reference


def test_integrity_failure_is_untrusted_but_never_auto_enforced() -> None:
    engine = ZeroTrustDeviceIdentityEngine()
    attestation, event = engine.verify(profile(), posture(evidence()), context={"integrity_failure": True, "evidence_reference": ["integrity:failure-1"]})
    assert attestation.trust_state == UNTRUSTED
    response = engine.emergency_response_context(attestation, event)
    assert response == {"eligible": True, "authorization_required": True, "automatic_action": False, "evidence_reference": list(event.evidence_reference), "recommended_workflow": "collect_evidence_then_request_investigation"}


def test_trust_recovers_after_remediation_and_records_previous_state() -> None:
    engine = ZeroTrustDeviceIdentityEngine()
    weak = evidence(); weak["unsigned_applications"] = 1
    previous, _ = engine.verify(profile(), posture(weak, "2026-07-17T10:00:00Z"))
    recovered, event = engine.verify(profile(), posture(evidence(), "2026-07-17T10:05:00Z"), previous=previous)
    assert previous.trust_state == CONDITIONAL
    assert recovered.trust_state == TRUSTED
    assert event.previous_trust_state == CONDITIONAL
    assert event.new_trust_state == TRUSTED


def test_repository_preserves_attestation_and_decision_history(tmp_path) -> None:
    engine = ZeroTrustDeviceIdentityEngine(); attestation, event = engine.verify(profile(), posture(evidence()))
    repository = DeviceIdentityRepository(tmp_path / "identity.sqlite3")
    repository.save(attestation, event)
    loaded = repository.latest_attestation("device-1")
    assert loaded and loaded.attestation_id == attestation.attestation_id
    assert repository.decision_history("device-1")[0]["event_id"] == event.event_id
    stored = repository.conn.execute("SELECT payload_json FROM device_identity").fetchone()[0]
    assert "C02-PRIVATE-SERIAL" not in stored
    repository.close()


def test_repository_detects_attestation_tampering(tmp_path) -> None:
    engine = ZeroTrustDeviceIdentityEngine(); attestation, event = engine.verify(profile(), posture(evidence()))
    repository = DeviceIdentityRepository(tmp_path / "tamper.sqlite3"); repository.save(attestation, event)
    payload = repository.conn.execute("SELECT payload_json FROM device_identity").fetchone()[0]
    repository.conn.execute("UPDATE device_identity SET payload_json=?", (payload.replace('"trust_score":100', '"trust_score":1'),)); repository.conn.commit()
    with pytest.raises(ValueError, match="integrity verification failed"):
        repository.latest_attestation("device-1")
    repository.close()


def test_dashboard_and_ai_context_are_decision_support_only() -> None:
    engine = ZeroTrustDeviceIdentityEngine(); attestation, event = engine.verify(profile(), posture(evidence()))
    dashboard = engine.dashboard(attestation, [event]); context = engine.analyst_context(attestation, event)
    assert dashboard["actions"] == ["verify_device", "view_evidence", "generate_attestation", "review_changes", "start_investigation"]
    assert "decision support only" in dashboard["authorization_notice"]
    assert "must not override policy" in context["guardrail"]


def test_decisive_external_context_without_evidence_fails_closed() -> None:
    with pytest.raises(ValueError, match="requires an evidence_reference"):
        ZeroTrustDeviceIdentityEngine().verify(profile(), posture(evidence()), context={"active_threat": True})


def test_reports_include_attestation_and_policy_qualification(tmp_path) -> None:
    engine = ZeroTrustDeviceIdentityEngine(); attestation, event = engine.verify(profile(), posture(evidence()))
    artifact = {"attestation": attestation.to_dict(), "decision": event.to_dict()}
    scan = ScanResult("scan-zt", attestation.timestamp, "mac.test", "analyst", collected_artifacts={"zero_trust_device_identity": artifact})
    json_path = export_scan_result_json(scan, tmp_path / "zt.json"); html_path = export_scan_result_html(scan, tmp_path / "zt.html")
    payload = json.loads(json_path.read_text(encoding="utf-8")); html = html_path.read_text(encoding="utf-8")
    assert payload["zero_trust_device_identity"]["attestation"]["trust_state"] == TRUSTED
    assert payload["report_summary"]["zero_trust_device_identity"]["attestation"]["attestation_hash"] == attestation.attestation_hash
    assert "Zero Trust Device Identity" in html
    assert "does not grant, deny, or revoke" in html


def test_existing_zero_trust_panel_displays_device_attestation() -> None:
    from PySide6.QtWidgets import QApplication
    from mac_audit_agent.ui.zero_trust_panel import ZeroTrustPosturePanel
    app = QApplication.instance() or QApplication([])
    panel = ZeroTrustPosturePanel()
    panel.set_device_identity({"trust_state": CONDITIONAL, "trust_score": 82, "timestamp": "2026-07-17T10:00:00Z", "evidence_coverage_percent": 90})
    assert "CONDITIONAL TRUST" in panel.identity.text()
    assert "Decision support only" in panel.identity.text()
    panel.close()
