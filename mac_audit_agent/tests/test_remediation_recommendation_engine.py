from __future__ import annotations

import json

from mac_audit_agent.frameworks.source_registry import official_framework_sources
from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.remediation.cisa_kev_enrichment import generate_kev_priority
from mac_audit_agent.remediation.mitre_mapper import generate_mitre_mitigation_guidance
from mac_audit_agent.remediation.recommendation_engine import build_recommended_fix, enrich_finding_with_recommendation


def test_cve_finding_generates_nvd_unavailable_recommendation_without_fabrication() -> None:
    finding = {
        "id": "f1",
        "title": "Vulnerable app CVE-2099-12345",
        "severity": "high",
        "category": "Vulnerability",
        "evidence": "Detected ExampleApp 1.0 with CVE-2099-12345",
        "detected_product": "ExampleApp",
        "detected_version": "1.0",
    }
    fix = build_recommended_fix(finding).to_dict()
    assert fix["finding_type"] == "vulnerability_cve"
    assert fix["recommended_fix"]
    assert fix["cve_context"]["cves"][0]["available"] is False
    assert "NVD enrichment unavailable" in json.dumps(fix)
    assert "threat actor" not in fix["summary"].lower()


def test_kev_context_does_not_claim_local_compromise() -> None:
    finding = {"id": "kev", "title": "KEV CVE-2099-99999", "cve_ids": ["CVE-2099-99999"], "kev": True, "severity": "critical"}
    kev = generate_kev_priority(finding)
    assert "not confirmed compromise" in json.dumps(kev)
    fix = build_recommended_fix(finding).to_dict()
    assert "not confirmed local compromise" in json.dumps(fix) or "not confirmed compromise" in json.dumps(fix)


def test_mitre_mapping_includes_mitigation_guidance_without_actor_attribution() -> None:
    finding = {"id": "la", "title": "New LaunchAgent added", "category": "Persistence", "severity": "medium"}
    mitre = generate_mitre_mitigation_guidance(finding)
    assert mitre["techniques"][0]["technique_id"] == "T1543.001"
    assert mitre["mitigations"]
    assert "actor" not in json.dumps(mitre).lower()


def test_unknown_suspicious_finding_does_not_invent_cve_or_actor() -> None:
    finding = {"id": "unknown", "title": "Unclassified suspicious behavior", "finding_type": "emerging_ttp_no_cve", "severity": "high"}
    fix = build_recommended_fix(finding).to_dict()
    text = json.dumps(fix)
    assert "No CVE" in text
    assert fix["actor_attribution_status"] == "insufficient_evidence"
    assert "zero-day label is assigned" in text


def test_every_finding_enriched_with_false_positive_and_poam() -> None:
    enriched = enrich_finding_with_recommendation({"id": "net", "title": "Hidden localhost port", "severity": "medium"})
    assert enriched["recommended_fix"]["recommended_fix"]
    assert enriched["false_positive_review"]["checks"]
    assert enriched["poam"]["recommended_fix"]
    assert enriched["apple_diagnostics_export_options"]


def test_source_registry_has_remediation_and_apple_sources() -> None:
    ids = {source.source_id for source in official_framework_sources()}
    for required in {
        "nvd_cve_api",
        "nvd_cve_data_feeds",
        "cisa_kev_catalog",
        "mitre_attack_enterprise_mitigations",
        "apple_feedback_assistant",
        "apple_activity_monitor_system_diagnostics",
        "apple_diagnostics",
        "apple_wireless_diagnostics",
        "apple_security_reporting",
    }:
        assert required in ids


def test_pre_uat_registry_includes_remediation_and_apple_checks() -> None:
    ids = {check.check_id for check in build_registry()}
    for required in {
        "remediation.recommendations_present",
        "remediation.cve_enrichment",
        "remediation.cisa_kev_priority",
        "remediation.mitre_mapping",
        "remediation.no_fake_attribution",
        "remediation.false_positive_review",
        "apple_diagnostics.export_menu",
        "apple_diagnostics.package_generation",
        "apple_diagnostics.privacy_redaction",
        "reports.recommended_fixes",
        "poam.remediation_tracking",
    }:
        assert required in ids
