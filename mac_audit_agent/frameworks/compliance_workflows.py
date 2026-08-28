"""Professional workflow models that remain independent of GUI and storage."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from mac_audit_agent.compat.enum import StrEnum
from typing import Any
from uuid import uuid4


class AssetCategory(StrEnum):
    CUI_ASSET = "CUI_ASSET"
    SECURITY_PROTECTION_ASSET = "SECURITY_PROTECTION_ASSET"
    CONTRACTOR_RISK_MANAGED_ASSET = "CONTRACTOR_RISK_MANAGED_ASSET"
    SPECIALIZED_ASSET = "SPECIALIZED_ASSET"
    OUT_OF_SCOPE_ASSET = "OUT_OF_SCOPE_ASSET"


@dataclass
class ContractApplicability:
    organization_name: str
    business_unit: str
    contract_number: str
    solicitation_number: str
    prime_or_subcontractor: str
    clauses: list[str]
    handles_fci: bool
    handles_cui: bool
    handles_cdi: bool
    operationally_critical_support: bool
    required_cmmc_level: int | None
    required_assessment_type: str
    required_status_date: str = ""
    flowdown_obligations: list[str] = field(default_factory=list)
    contract_specific_language: str = ""

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.organization_name: errors.append("organization name is required")
        if not self.contract_number and not self.solicitation_number: errors.append("contract or solicitation is required")
        if self.handles_cui and "252.204-7012" not in " ".join(self.clauses): errors.append("CUI handling requires reviewer confirmation of DFARS 252.204-7012 applicability")
        if self.required_cmmc_level not in {1, 2, 3}: errors.append("required CMMC level is unresolved")
        if not self.required_assessment_type: errors.append("assessment type is unresolved")
        return errors


@dataclass
class Asset:
    asset_id: str
    name: str
    category: AssetCategory
    system_id: str
    location_id: str
    handles_fci: bool = False
    handles_cui: bool = False
    rationale: str = ""


@dataclass
class DataFlow:
    flow_id: str
    source_asset_id: str
    destination_asset_id: str
    information_type: str
    encrypted: bool | None
    external_connection: bool = False
    unresolved_questions: list[str] = field(default_factory=list)


@dataclass
class ExternalProvider:
    provider_id: str
    name: str
    service: str
    handles_fci_or_cui: bool
    customer_responsibilities: list[str]
    provider_responsibilities: list[str]
    evidence_ids: list[str]
    fedramp_status_or_equivalency: str = ""
    unresolved_responsibilities: list[str] = field(default_factory=list)

    def inheritance_valid(self) -> bool:
        return bool(self.evidence_ids) and not self.unresolved_responsibilities and bool(self.customer_responsibilities) and bool(self.provider_responsibilities)


@dataclass
class Supplier:
    supplier_id: str
    name: str
    information_shared: str
    applicable_clauses: list[str]
    required_cmmc_level: int | None
    status_expiration: str = ""
    affirmation_date: str = ""
    incident_notification_required: bool = False
    flowdown_evidence_ids: list[str] = field(default_factory=list)


@dataclass
class AssessmentScope:
    scope_id: str
    name: str
    contract: ContractApplicability
    assets: list[Asset]
    data_flows: list[DataFlow]
    providers: list[ExternalProvider]
    suppliers: list[Supplier]
    boundary_statement: str
    locations: list[str]
    systems: list[str]
    enclaves: list[str]
    unresolved_questions: list[str] = field(default_factory=list)

    def validate(self) -> dict[str, Any]:
        issues = self.contract.validate() + list(self.unresolved_questions)
        if not self.boundary_statement: issues.append("boundary statement is required")
        if not self.assets: issues.append("asset inventory is empty")
        asset_ids = {asset.asset_id for asset in self.assets}
        for flow in self.data_flows:
            if flow.source_asset_id not in asset_ids or flow.destination_asset_id not in asset_ids: issues.append(f"data flow {flow.flow_id} references missing asset")
            issues.extend(f"data flow {flow.flow_id}: {item}" for item in flow.unresolved_questions)
        for provider in self.providers:
            if provider.handles_fci_or_cui and not provider.inheritance_valid(): issues.append(f"provider {provider.provider_id} responsibility/evidence unresolved")
        for asset in self.assets:
            if asset.category is AssetCategory.OUT_OF_SCOPE_ASSET and not asset.rationale: issues.append(f"out-of-scope asset {asset.asset_id} lacks rationale")
        return {"complete": not issues, "issues": issues, "status": "COMPLETE" if not issues else "BLOCKED_BY_SCOPE", "error_code": "" if not issues else "SCP001"}


@dataclass
class ExamineRecord:
    record_id: str
    objective_ids: list[str]
    evidence_ids: list[str]
    object_examined: str
    version: str
    owner: str
    scope_id: str
    relevant_section: str
    analyst_notes: str
    reviewer_notes: str = ""
    limitations: list[str] = field(default_factory=list)


@dataclass
class InterviewRecord:
    record_id: str
    objective_ids: list[str]
    interviewee_role: str
    questions: list[str]
    responses: list[str]
    interviewer: str
    interview_date: str
    witnesses: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    privacy_classification: str = "PROPRIETARY"

    def complete(self) -> bool:
        return bool(self.questions) and len(self.questions) == len(self.responses) and all(response.strip() for response in self.responses)


@dataclass
class TestExecution:
    execution_id: str
    objective_ids: list[str]
    test_objective: str
    procedure: list[str]
    expected_result: str
    actual_result: str
    tester: str
    scope_id: str
    authorized: bool
    intrusive: bool = False
    cleanup: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def valid(self) -> bool:
        return self.authorized and (not self.intrusive or bool(self.cleanup)) and bool(self.actual_result)


@dataclass
class SSPControlImplementation:
    requirement_id: str
    who: str
    what: str
    where: str
    when: str
    how: str
    assets_and_data: str
    evidence_ids: list[str]
    inherited_provider_id: str = ""
    owner_reviewed: bool = False

    def valid(self) -> bool:
        return all((self.who, self.what, self.where, self.when, self.how, self.assets_and_data)) and bool(self.evidence_ids) and self.owner_reviewed


@dataclass
class POAMRecord:
    poam_id: str
    requirement_id: str
    failed_objective_ids: list[str]
    gap_description: str
    root_cause: str
    planned_remediation: str
    owner: str
    conditional_status_date: str
    eligibility: bool
    eligibility_source: str
    critical_control_exclusion: bool = False
    milestones: list[dict[str, str]] = field(default_factory=list)
    reviewer_approved: bool = False

    def validate(self) -> dict[str, Any]:
        start = date.fromisoformat(self.conditional_status_date)
        deadline = start + timedelta(days=180)
        allowed = self.eligibility and bool(self.eligibility_source) and not self.critical_control_exclusion
        return {"valid": allowed and self.reviewer_approved, "closeout_deadline": deadline.isoformat(), "days_remaining": (deadline - date.today()).days, "overdue": date.today() > deadline, "error_code": "" if allowed else "POA001"}


@dataclass
class AffirmationRecord:
    affirmation_id: str
    level: int
    assessment_id: str
    affirming_official: str
    acknowledgement_text: str
    acknowledged: bool
    affirmed_at: str = ""

    def record(self) -> None:
        if not self.acknowledged or not self.acknowledgement_text.strip():
            raise ValueError("AFF001 explicit acknowledgement is required before affirmation")
        self.affirmed_at = datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


__all__ = ["AssetCategory", "ContractApplicability", "Asset", "DataFlow", "ExternalProvider", "Supplier", "AssessmentScope", "ExamineRecord", "InterviewRecord", "TestExecution", "SSPControlImplementation", "POAMRecord", "AffirmationRecord", "new_id"]
