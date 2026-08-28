from mac_audit_agent.security_control_database import BASE_RECORDS, SecurityControlDatabase, SecurityControlRecord

def test_registry_has_cross_cutting_security_categories_and_valid_records():
    db=SecurityControlDatabase();assert {"persistence","identity","ransomware","supply_chain","network","integrity","privacy","evidence","assurance","device_identity","posture_graph","threat_exposure","control_validation","supply_trust_graph","software_attestation","security_regression","cyber_resilience"}.issubset(db.categories())
    assert all(record.evidence_required and record.remediation and record.source_modules for record in BASE_RECORDS)

def test_finding_resolution_combines_canonical_and_existing_framework_engine():
    result=SecurityControlDatabase().resolve_finding({"event_type":"ssh_identity_change","category":"identity","mitre_attack":["T1098"],"evidence":"fingerprint changed"})
    assert result["mapped"] and result["canonical_control"]["record_id"]=="control.identity";assert result["finding_mappings"]

def test_unmapped_findings_are_explicit_not_silently_compliant():
    result=SecurityControlDatabase().resolve_finding({"category":"novel_unknown"});assert not result["mapped"] and result["limitations"]

def test_existing_monitor_and_command_registries_are_available_without_duplication():
    db=SecurityControlDatabase();assert any(x["control_id"]=="macos.sip" for x in db.monitored_controls());assert db.command_mapping("assurance.install_history")["evidence_use"]

def test_invalid_mitre_identifier_fails_registry_construction():
    bad=SecurityControlRecord("bad","bad","Bad",("TXYZ",),(),(),(),(),("review",),("evidence",),("test",))
    try:SecurityControlDatabase((bad,))
    except ValueError as exc:assert "MITRE" in str(exc)
    else:raise AssertionError("invalid mapping accepted")

def test_continuous_assurance_changes_resolve_to_ca7_control():
    result=SecurityControlDatabase().resolve_finding({"category":"continuous_security_assurance","title":"Firewall regression"})
    assert result["mapped"] and "CA-7" in result["canonical_control"]["nist_controls"]

def test_zero_trust_identity_resolves_to_device_identity_control():
    result=SecurityControlDatabase().resolve_finding({"category":"zero_trust_device_identity","title":"Trust changed"})
    assert result["canonical_control"]["record_id"]=="control.device_identity" and "IA-9" in result["canonical_control"]["nist_controls"]

def test_security_posture_graph_resolves_to_monitoring_control():
    result=SecurityControlDatabase().resolve_finding({"category":"security_posture_graph","title":"Correlated risk path"})
    assert result["canonical_control"]["record_id"]=="control.posture_graph" and "SI-4" in result["canonical_control"]["nist_controls"]

def test_threat_exposure_resolves_to_risk_assessment_control():
    result=SecurityControlDatabase().resolve_finding({"category":"threat_exposure_management","title":"KEV exposure"})
    assert result["canonical_control"]["record_id"]=="control.threat_exposure" and "RA-5" in result["canonical_control"]["nist_controls"]

def test_control_validation_resolves_to_configuration_control():
    result=SecurityControlDatabase().resolve_finding({"category":"security_control_validation","title":"Firewall failed"})
    assert result["canonical_control"]["record_id"]=="control.validation" and "CM-6" in result["canonical_control"]["nist_controls"]

def test_supply_trust_graph_resolves_to_sr_control():
 result=SecurityControlDatabase().resolve_finding({"category":"supply_chain_trust_graph","title":"Dependency risk"});assert result["canonical_control"]["record_id"]=="control.supply_trust_graph" and "SR-4" in result["canonical_control"]["nist_controls"]

def test_software_attestation_resolves_to_integrity_control():
 result=SecurityControlDatabase().resolve_finding({"category":"software_attestation","title":"Binary hash changed"});assert result["canonical_control"]["record_id"]=="control.software_attestation" and "SI-7" in result["canonical_control"]["nist_controls"]

def test_security_regression_resolves_to_change_control():
 result=SecurityControlDatabase().resolve_finding({"category":"security_regression_detection","title":"Firewall regressed"});assert result["canonical_control"]["record_id"]=="control.security_regression" and "CM-3" in result["canonical_control"]["nist_controls"]

def test_cyber_resilience_resolves_to_incident_readiness_control():
 result=SecurityControlDatabase().resolve_finding({"category":"cyber_resilience_score","title":"Recovery readiness low"});assert result["canonical_control"]["record_id"]=="control.cyber_resilience" and "IR-4" in result["canonical_control"]["nist_controls"]
