from __future__ import annotations

from datetime import datetime, timezone

from mac_audit_agent.frameworks.assessment_models import AssessmentObjective, Determination, EvidenceRecord, EvidenceRelationship, RequirementAssessment, aggregate_assessment_hash, append_audit_entry
from mac_audit_agent.frameworks.incident_readiness import DFARSIncident
from mac_audit_agent.frameworks.scoring import score_assessment
from mac_audit_agent.frameworks.standards_profiles import PROFILES, validate_catalog, validate_profile_isolation
from mac_audit_agent.frameworks.compliance_workflows import AffirmationRecord, Asset, AssetCategory, AssessmentScope, ContractApplicability, DataFlow, ExternalProvider, InterviewRecord, POAMRecord, SSPControlImplementation, TestExecution as ComplianceTestExecution
from mac_audit_agent.frameworks.report_conformance import ConformanceStatus, evaluate_report
from mac_audit_agent.frameworks.content_pack import StandardsContentPack, load_pack


def _objective(objective_id: str, parent: str, relationship: EvidenceRelationship, analyst=Determination.MET, reviewer=Determination.MET, signed=True):
    return AssessmentObjective(objective_id, parent, ("EXAMINE",), ("CONFIGURATION_EVIDENCE",), evidence_relationships=[("evd-1", relationship)], analyst_determination=analyst, reviewer_determination=reviewer, reviewer="reviewer", reviewer_signed_at=datetime.now(timezone.utc).isoformat() if signed else "")


def test_future_profile_cannot_drive_current_cmmc_score() -> None:
    assert validate_profile_isolation("nist_171_r3_future", requested_for_current_score=True)["allowed"] is False
    result = score_assessment("nist_171_r3_future", [])
    assert result.score is None and result.error_code == "STD003"


def test_incomplete_catalog_blocks_scoring_and_reports_missing_count() -> None:
    result = validate_catalog("cmmc_l2_current", ["3.1.1"], ["3.1.1"])
    assert result["status"] == "BLOCKER"
    assert result["missing_requirement_count"] == 109
    score = score_assessment("cmmc_l2_current", [RequirementAssessment("3.1.1", [], scope_resolved=True)], official_weights={"3.1.1": 5})
    assert score.status == "INVALID" and score.score is None


def test_supporting_or_stale_evidence_never_auto_meets_objective() -> None:
    for relationship in (EvidenceRelationship.SUPPORTING, EvidenceRelationship.STALE, EvidenceRelationship.OUT_OF_SCOPE, EvidenceRelationship.CONTRADICTORY):
        assert _objective("3.1.1[a]", "3.1.1", relationship).determine() is Determination.NOT_ASSESSED


def test_one_unmet_objective_prevents_requirement_met() -> None:
    assessment = RequirementAssessment("3.1.1", [_objective("3.1.1[a]", "3.1.1", EvidenceRelationship.DIRECT), _objective("3.1.1[b]", "3.1.1", EvidenceRelationship.DIRECT, analyst=Determination.NOT_MET, reviewer=Determination.NOT_MET)], applicability_rationale="contract", scope_resolved=True)
    assert assessment.determination() is Determination.NOT_MET


def test_reviewer_signoff_is_required() -> None:
    assert _objective("3.1.1[a]", "3.1.1", EvidenceRelationship.DIRECT, signed=False).determine() is Determination.NOT_ASSESSED


def test_evidence_hash_aggregate_tamper_and_append_only_audit(tmp_path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("original", encoding="utf-8")
    record = EvidenceRecord.from_file(artifact, title="Test", evidence_class="TEST_RECORD", collector="analyst", scope_id="scope-1")
    assert record.verify(artifact)
    assert len(aggregate_assessment_hash([record])) == 64
    artifact.write_text("tampered", encoding="utf-8")
    assert not record.verify(artifact)
    log = tmp_path / "audit.jsonl"
    first = append_audit_entry(log, user="a", role="ANALYST", action="COLLECT", reason="test")
    second = append_audit_entry(log, user="r", role="REVIEWER", action="REVIEW", reason="test")
    assert second["previous_hash"] == first["integrity_hash"]
    assert len(log.read_text().splitlines()) == 2


def test_dfars_incident_clocks_and_no_automatic_submission() -> None:
    incident = DFARSIncident("inc-1", datetime.now(timezone.utc).isoformat(), ["contract-1"], "under review", "none observed")
    package = incident.prepare_package()
    assert package["submission_performed"] is False
    assert package["deadlines"]["report_hours_remaining"] <= 72
    assert "never submits" in package["warning"]


def test_expected_current_profile_counts_are_isolated() -> None:
    assert PROFILES["cmmc_l1_current"].expected_requirement_count == 15
    assert PROFILES["cmmc_l2_current"].expected_requirement_count == 110
    assert PROFILES["cmmc_l3_current"].expected_requirement_count == 134


def _contract() -> ContractApplicability:
    return ContractApplicability("Org", "Unit", "C-1", "", "prime", ["DFARS 252.204-7012"], False, True, True, False, 2, "Level 2 Self")


def test_unresolved_scope_and_provider_evidence_block_completion() -> None:
    provider = ExternalProvider("esp-1", "Provider", "SIEM", True, ["configure"], ["operate"], [], unresolved_responsibilities=["incident notice"])
    scope = AssessmentScope("scope-1", "CUI enclave", _contract(), [Asset("a-1", "Mac", AssetCategory.CUI_ASSET, "sys-1", "loc-1", handles_cui=True)], [], [provider], [], "Boundary", ["loc-1"], ["sys-1"], ["enc-1"])
    result = scope.validate()
    assert result["complete"] is False and result["error_code"] == "SCP001"
    assert any("provider esp-1" in issue for issue in result["issues"])


def test_missing_data_flow_asset_blocks_scope() -> None:
    flow = DataFlow("flow-1", "missing", "also-missing", "CUI", True)
    scope = AssessmentScope("scope-1", "CUI enclave", _contract(), [Asset("a-1", "Mac", AssetCategory.CUI_ASSET, "sys-1", "loc-1")], [flow], [], [], "Boundary", ["loc-1"], ["sys-1"], ["enc-1"])
    assert scope.validate()["status"] == "BLOCKED_BY_SCOPE"


def test_interview_never_fabricates_missing_response() -> None:
    interview = InterviewRecord("int-1", ["3.1.1[a]"], "Administrator", ["How is access approved?"], [""], "Analyst", "2026-07-10")
    assert interview.complete() is False


def test_intrusive_test_requires_authorization_and_cleanup() -> None:
    execution = ComplianceTestExecution("test-1", ["3.1.1[a]"], "Validate", ["safe action"], "blocked", "blocked", "Analyst", "scope-1", True, intrusive=True)
    assert execution.valid() is False
    execution.cleanup = "restore state"
    assert execution.valid() is True


def test_ssp_requires_who_what_where_when_how_evidence_and_review() -> None:
    statement = SSPControlImplementation("3.1.1", "Admin", "Reviews users", "Enclave", "Monthly", "Ticket workflow", "CUI assets", ["evd-1"])
    assert statement.valid() is False
    statement.owner_reviewed = True
    assert statement.valid() is True


def test_poam_rejects_critical_or_unsourced_eligibility() -> None:
    poam = POAMRecord("poam-1", "3.1.1", ["3.1.1[a]"], "Gap", "Cause", "Fix", "Owner", "2026-07-10", True, "", critical_control_exclusion=True, reviewer_approved=True)
    result = poam.validate()
    assert result["valid"] is False and result["error_code"] == "POA001"


def test_affirmation_requires_explicit_acknowledgement() -> None:
    record = AffirmationRecord("aff-1", 2, "assessment-1", "Official", "", False)
    try:
        record.record()
    except ValueError as exc:
        assert "AFF001" in str(exc)
    else:
        raise AssertionError("affirmation was recorded without acknowledgement")


def test_report_missing_catalog_is_incomplete_and_false_claim_is_invalid() -> None:
    payload = {"header": {"report_title": "Readiness", "disclaimer": "Not certification"}, "requirements": [{"requirement_id": "3.1.1", "determination": "NOT_ASSESSED"}], "objectives": [], "profiles_separated": True}
    assert evaluate_report(payload, expected_requirements=110, expected_objectives=None).status is ConformanceStatus.INCOMPLETE
    payload["summary"] = "CMMC certified"
    assert evaluate_report(payload, expected_requirements=110, expected_objectives=None).status is ConformanceStatus.INVALID


def test_content_pack_cannot_activate_without_hash_review_tests_and_approval(tmp_path) -> None:
    pack = StandardsContentPack("pack-1", "1", "cmmc_l1_current", [{"official_domain": True, "document_sha256": "a" * 64}], [{"requirement_id": "r1"}], [{"objective_id": "r1[a]", "requirement_id": "r1"}], "parser-1", previous_pack_id="pack-0", migration_notes=["review changes"])
    validation = pack.validate_activation(expected_requirements=1, expected_objectives=1)
    assert validation["activatable"] is False
    assert validation["gates"]["tests_validated"] is False
    written = pack.write(tmp_path / "pack.json")
    assert len(written["content_pack_sha256"]) == 64
    loaded = load_pack(tmp_path / "pack.json")
    assert loaded.previous_pack_id == "pack-0"
