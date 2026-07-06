from __future__ import annotations

from mac_audit_agent.frameworks.cmmc import build_cmmc_readiness, cmmc_requirements
from mac_audit_agent.frameworks.cmmc_crosswalk import map_msaa_check_to_cmmc, map_cmmc_to_nist
from mac_audit_agent.frameworks.poam import poam_from_cmmc_readiness
from mac_audit_agent.frameworks.source_registry import OFFICIAL_SOURCE_DOMAINS, official_framework_sources
from mac_audit_agent.quality.audit_models import AuditContext
from mac_audit_agent.quality.cmmc_auditor import run_cmmc_audit


def test_cmmc_and_nist_source_registry_uses_official_sources() -> None:
    sources = official_framework_sources()
    assert any(source.source_id == "cmmc_32_cfr_170" for source in sources)
    assert any(source.source_id == "nist_sp_800_171_r3" for source in sources)
    assert any(source.framework == "DFARS" for source in sources)
    assert any(source.framework == "CISA" for source in sources)
    assert any(source.framework == "NSA" for source in sources)
    assert any(source.framework == "PCI" for source in sources)
    assert any(source.framework == "MITRE" for source in sources)
    for source in sources:
        assert source.version
        assert source.retrieved_at
        assert source.source_type in {"government_standard", "government_guidance", "industry_standard", "public_reference"}
        assert source.source_url.startswith("https://")
        assert any(domain in source.source_url for domain in OFFICIAL_SOURCE_DOMAINS)


def test_every_cmmc_requirement_has_source_and_manual_limits_are_not_auto_met() -> None:
    requirements = cmmc_requirements()
    assert requirements
    for requirement in requirements:
        assert requirement.source_id
        assert requirement.source_version
        assert requirement.assessment_method in {"examine", "interview", "test", "unknown"}
    readiness = build_cmmc_readiness(completed_check_ids={"scan.physical_devices"})
    manual = [item for item in readiness.requirements if item.get("limitations")]
    assert manual
    assert all(item["implementation_status"] != "met" for item in manual)


def test_cmmc_crosswalk_marks_partial_and_manual_evidence() -> None:
    mappings = map_msaa_check_to_cmmc("scan.physical_devices")
    assert mappings
    assert all(mapping["mapping_confidence"] in {"direct", "partial", "supporting_evidence", "manual_review_required", "not_applicable"} for mapping in mappings)
    assert any(mapping["manual_evidence_required"] for mapping in mappings)
    assert map_cmmc_to_nist("CMMC-L2-MP-1")


def test_cmmc_readiness_payload_and_poam_are_report_ready() -> None:
    readiness = build_cmmc_readiness(completed_check_ids={"scan.apple_exposure", "scan.physical_devices", "network_intelligence.collectors"})
    payload = readiness.to_dict()
    assert payload["source_versions"]
    assert payload["requirements"]
    assert payload["evidence_items"]
    assert "not a CMMC" in payload["disclaimer"]
    poam = poam_from_cmmc_readiness(payload)
    assert poam
    assert all(item.framework == "CMMC" for item in poam)


def test_cmmc_pre_uat_checks_pass(tmp_path) -> None:
    context = AuditContext(db_path=tmp_path / "audit.sqlite", output_dir=tmp_path, mode="frameworks")
    checks = run_cmmc_audit(context)
    assert {check.check_id for check in checks} >= {
        "standards.comparative_review_generated",
        "standards.ip_safety_review_generated",
        "standards.no_plagiarism_guardrails",
        "standards.derived_idea_matrix_valid",
        "standards.official_source_registry",
        "standards.no_false_claims",
        "standards.accepted_ideas_have_mappings",
        "frameworks.cmmc_source_registry",
        "frameworks.cmmc_mapping_integrity",
        "frameworks.cmmc_readiness_dashboard",
        "frameworks.cmmc_reports",
        "frameworks.no_false_claims",
        "frameworks.cmmc_manual_evidence",
        "acknowledgements.nsa_separate_from_author",
        "support_author.final_tab",
    }
    assert all(check.status == "PASS" for check in checks)
