from __future__ import annotations

import json

import pytest

from mac_audit_agent.threat_exposure_management import ExposureAsset, ThreatExposureManagementEngine, ThreatExposureRepository, ThreatIntelligenceMatch, version_is_affected
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json


def asset(**updates) -> ExposureAsset:
    values = {"asset_id": "device-1", "asset_type": "macos_endpoint", "importance": "administrator", "trust_state": "CONDITIONAL TRUST", "security_score": 78, "compliance_state": "needs_review", "internet_exposure": "user_exposed", "privileged_user": True, "evidence_reference": ("device:attestation-1",)}
    values.update(updates); return ExposureAsset(**values)


def software(version="1.4", **updates):
    value = {"name": "Example Browser", "product": "example browser", "version": version, "signature_status": "valid", "evidence_reference": ["inventory:browser-1"]}; value.update(updates); return value


def vulnerability(**updates):
    value = {"cve_id": "CVE-2026-12345", "product": "example browser", "fixed_version": "2.0", "cvss_score": 8.1, "source": "NVD", "evidence_reference": ["nvd:CVE-2026-12345"], "mitre_mapping": ["T1190"]}; value.update(updates); return value


def kev():
    return ThreatIntelligenceMatch("cve", "CVE-2026-12345", "CISA KEV", "2026-07-17T00:00:00Z", "high", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "known_exploited")


def test_version_applicability_is_deterministic_and_unknown_fails_closed() -> None:
    assert version_is_affected("1.4", fixed_version="2.0") is True
    assert version_is_affected("2.0", fixed_version="2.0") is False
    assert version_is_affected("1.4", affected_version="<=1.5") is True
    assert version_is_affected("not-a-version", fixed_version="2.0") is None


def test_vulnerable_application_creates_evidence_backed_exposure() -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], timestamp="2026-07-17T10:00:00Z")
    exposure = assessment.exposures[0]
    assert exposure.cve_id == "CVE-2026-12345" and exposure.cvss_score == 8.1
    assert {"inventory:browser-1", "nvd:CVE-2026-12345"}.issubset(exposure.evidence_reference)
    assert "does not indicate local exploitation" in exposure.risk_explanation


def test_non_affected_or_product_mismatch_does_not_create_false_exposure() -> None:
    engine = ThreatExposureManagementEngine()
    assert engine.assess(asset(), software=[software("2.0")], vulnerabilities=[vulnerability()]).exposures == ()
    assert engine.assess(asset(), software=[software()], vulnerabilities=[vulnerability(product="different")]).exposures == ()


def test_kev_increases_priority_but_never_claims_endpoint_exploitation() -> None:
    engine = ThreatExposureManagementEngine()
    ordinary = engine.assess(asset(), software=[software()], vulnerabilities=[vulnerability()]).exposures[0]
    known = engine.assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[kev()]).exposures[0]
    assert known.exposure_score > ordinary.exposure_score
    assert known.exploit_status == "known_exploited_in_wild"
    assert "CISA KEV" in known.threat_source
    assert "not confirmed exploitation" in engine.analyst_context(known)["guardrail"]


def test_cvss_alone_cannot_produce_same_priority_as_kev_asset_context() -> None:
    engine = ThreatExposureManagementEngine()
    low_context = engine.assess(asset(importance="standard", privileged_user=False, internet_exposure="local", trust_state="TRUSTED"), software=[software()], vulnerabilities=[vulnerability(cvss_score=10)]).exposures[0]
    contextual = engine.assess(asset(importance="critical_infrastructure", internet_exposure="internet_reachable"), software=[software()], vulnerabilities=[vulnerability(cvss_score=6.5)], threat_intelligence=[kev()]).exposures[0]
    assert contextual.exposure_score > low_context.exposure_score
    assert len(contextual.score_factors) > 4


def test_invalid_intelligence_is_ignored_and_uncertainty_exposed() -> None:
    invalid = {"indicator_type": "cve", "indicator_value": "CVE-2026-12345", "source": "", "timestamp": "", "confidence": "high", "reference": "", "status": "known_exploited"}
    exposure = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[invalid]).exposures[0]
    assert exposure.exploit_status == "unknown"
    assert any("No valid threat-intelligence" in item for item in exposure.uncertainty)


def test_graph_path_adds_context_only_when_component_is_supported() -> None:
    graph = {"risk_paths": [{"path_id": "p1", "evidence_reference": ["inventory:browser-1"], "observed_facts": ["Example Browser installed"]}]}
    exposure = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], posture_graph=graph).exposures[0]
    assert any("graph path" in item.lower() for item in exposure.score_factors)


def test_configuration_identity_and_supply_chain_exposures_are_ranked() -> None:
    refs = lambda name: {"title": name, "affected_component": name, "severity": "high", "evidence_reference": [f"event:{name}"], "recommendation": f"Review {name}."}
    assessment = ThreatExposureManagementEngine().assess(asset(), configuration_findings=[{**refs("Firewall disabled"), "previous_state": "enabled", "current_state": "disabled"}], identity_findings=[refs("New administrator")], supply_chain_findings=[refs("Unsigned dependency")])
    assert {item.risk_category for item in assessment.exposures} == {"configuration", "identity", "supply_chain"}
    config = next(item for item in assessment.exposures if item.risk_category == "configuration")
    assert config.previous_state == "enabled" and config.current_state == "disabled"


def test_missing_evidence_suppresses_generic_exposure() -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(evidence_reference=()), configuration_findings=[{"title": "Firewall disabled", "severity": "critical"}])
    assert assessment.exposures == ()


def test_ranking_and_expected_risk_reduction_are_explained() -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[kev()], configuration_findings=[{"title": "Sharing enabled", "severity": "medium", "evidence_reference": ["config:sharing"]}])
    assert assessment.remediation_order[0] == assessment.exposures[0].exposure_id
    assert assessment.exposures[0].expected_risk_reduction > 0
    assert assessment.score_explanation[0].startswith("1.")


def test_trend_tracks_new_resolved_and_recurring() -> None:
    engine = ThreatExposureManagementEngine()
    previous = engine.assess(asset(), software=[software()], vulnerabilities=[vulnerability()], timestamp="2026-07-01T00:00:00Z")
    current = engine.assess(asset(), configuration_findings=[{"title": "Firewall disabled", "evidence_reference": ["config:1"], "severity": "high"}], timestamp="2026-07-17T00:00:00Z")
    trend = engine.trend(current, previous)
    assert trend["new"] == 1 and trend["resolved"] == 1 and trend["recurring"] == 0
    assert trend["average_remediation_seconds"] == 16 * 24 * 60 * 60
    assert "Upper-bound" in trend["remediation_time_qualification"]


def test_string_framework_and_source_values_are_not_split_into_characters() -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), configuration_findings=[{"title": "Firewall disabled", "evidence_reference": ["config:1"], "mitre_mapping": "T1562.004", "threat_source": "baseline_drift"}])
    exposure = assessment.exposures[0]
    assert exposure.mitre_mapping == ("T1562.004",) and exposure.threat_source == ("baseline_drift",)


def test_incident_and_dashboard_actions_require_human_authorization() -> None:
    engine = ThreatExposureManagementEngine(); assessment = engine.assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[kev()])
    exposure = assessment.exposures[0]; incident = engine.incident_context(exposure); dashboard = engine.dashboard(assessment)
    assert incident["authorization_required"] and not incident["automatic_action"]
    assert "create_ticket" in dashboard["actions"] and dashboard["known_exploited_vulnerabilities"]


def test_sensitive_input_fields_are_not_persisted_in_exposure() -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), software=[software(password="do-not-store")], vulnerabilities=[vulnerability()])
    assert "do-not-store" not in json.dumps(assessment.to_dict())


def test_repository_preserves_assessment_and_detects_tampering(tmp_path) -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[kev()])
    repository = ThreatExposureRepository(tmp_path / "exposure.sqlite3"); repository.save(assessment)
    assert repository.latest_payload("device-1")["assessment_id"] == assessment.assessment_id
    repository.conn.execute("UPDATE exposure_assessments SET payload_json=replace(payload_json, 'known_exploited_in_wild', 'unknown')"); repository.conn.commit()
    with pytest.raises(ValueError, match="integrity verification failed"):
        repository.latest_payload("device-1")
    repository.close()


def test_reports_and_dashboard_panel_show_ranked_exposures(tmp_path) -> None:
    assessment = ThreatExposureManagementEngine().assess(asset(), software=[software()], vulnerabilities=[vulnerability()], threat_intelligence=[kev()])
    artifact = {"assessment": assessment.to_dict()}
    scan = ScanResult("scan-exposure", assessment.timestamp, "mac.test", "analyst", collected_artifacts={"threat_exposure_management": artifact})
    json_path = export_scan_result_json(scan, tmp_path / "exposure.json"); html_path = export_scan_result_html(scan, tmp_path / "exposure.html")
    payload = json.loads(json_path.read_text(encoding="utf-8")); html = html_path.read_text(encoding="utf-8")
    assert payload["threat_exposure_management"]["assessment"]["exposures"]
    assert payload["report_summary"]["threat_exposure_management"]["assessment"]["overall_exposure_score"] == assessment.overall_exposure_score
    assert "Threat Exposure Management" in html and "CVSS is not used alone" in html
    from PySide6.QtWidgets import QApplication
    from mac_audit_agent.ui.threat_exposure_panel import ThreatExposureManagementPanel
    app = QApplication.instance() or QApplication([]); panel = ThreatExposureManagementPanel(); panel.set_assessment(artifact)
    assert panel.table.rowCount() == 1 and "KEV: 1" in panel.summary.text()
    assert "does not prove exploitation" in panel.notice.text(); panel.close()
