"""Version-aware assessment-readiness primitives.

These models deliberately do not contain official determination authority.
They preserve the chain from source/profile through reviewer disposition.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from mac_audit_agent.compat.enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


class PlanningHorizon(StrEnum):
    CONTRACTUAL_CURRENT = "CONTRACTUAL_CURRENT"
    FINAL_FUTURE_READINESS = "FINAL_FUTURE_READINESS"
    DRAFT_EMERGING = "DRAFT_EMERGING"


class ReadinessState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    NOT_ASSESSED = "NOT_ASSESSED"
    EVIDENCE_REQUESTED = "EVIDENCE_REQUESTED"
    EVIDENCE_RECEIVED = "EVIDENCE_RECEIVED"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    PARTIALLY_EVIDENCED = "PARTIALLY_EVIDENCED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    TECHNICAL_CHECK_PASSED = "TECHNICAL_CHECK_PASSED"
    TECHNICAL_CHECK_FAILED = "TECHNICAL_CHECK_FAILED"
    INTERVIEW_REQUIRED = "INTERVIEW_REQUIRED"
    TEST_REQUIRED = "TEST_REQUIRED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
    BLOCKED_BY_DEPENDENCY = "BLOCKED_BY_DEPENDENCY"
    INHERITED_PENDING_VALIDATION = "INHERITED_PENDING_VALIDATION"
    COMPLETE = "COMPLETE"


class Determination(StrEnum):
    MET = "MET"
    NOT_MET = "NOT_MET"
    NOT_ASSESSED = "NOT_ASSESSED"


class EvidenceRelationship(StrEnum):
    DIRECT = "DIRECT"
    SUPPORTING = "SUPPORTING"
    CONTEXTUAL = "CONTEXTUAL"
    CONTRADICTORY = "CONTRADICTORY"
    INSUFFICIENT = "INSUFFICIENT"
    STALE = "STALE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class StandardsProfile:
    profile_id: str
    title: str
    horizon: PlanningHorizon
    source_ids: tuple[str, ...]
    expected_requirement_count: int
    expected_objective_count: int | None
    scoring_authority_source_id: str | None = None
    activated: bool = False
    activation_approved_by: str = ""
    activation_date: str = ""

    def may_drive_current_score(self) -> bool:
        return self.horizon is PlanningHorizon.CONTRACTUAL_CURRENT and self.activated and bool(self.activation_approved_by)


@dataclass
class AssessmentObjective:
    objective_id: str
    requirement_id: str
    methods_required: tuple[str, ...]
    expected_evidence_classes: tuple[str, ...]
    readiness_state: ReadinessState = ReadinessState.NOT_STARTED
    evidence_relationships: list[tuple[str, EvidenceRelationship]] = field(default_factory=list)
    analyst_determination: Determination = Determination.NOT_ASSESSED
    reviewer_determination: Determination = Determination.NOT_ASSESSED
    reviewer: str = ""
    reviewer_signed_at: str = ""
    limitations: list[str] = field(default_factory=list)

    def determine(self) -> Determination:
        relationships = {relationship for _, relationship in self.evidence_relationships}
        if relationships & {EvidenceRelationship.CONTRADICTORY, EvidenceRelationship.STALE, EvidenceRelationship.OUT_OF_SCOPE}:
            return Determination.NOT_ASSESSED
        if self.analyst_determination is Determination.MET and not self.reviewer_signed_at:
            return Determination.NOT_ASSESSED
        if self.reviewer_determination is Determination.MET and EvidenceRelationship.DIRECT in relationships:
            return Determination.MET
        if self.reviewer_determination is Determination.NOT_MET:
            return Determination.NOT_MET
        return Determination.NOT_ASSESSED


@dataclass
class RequirementAssessment:
    requirement_id: str
    objectives: list[AssessmentObjective]
    applicability_rationale: str = ""
    scope_resolved: bool = False

    def determination(self) -> Determination:
        if not self.scope_resolved or not self.objectives:
            return Determination.NOT_ASSESSED
        results = [objective.determine() for objective in self.objectives]
        if any(result is Determination.NOT_MET for result in results):
            return Determination.NOT_MET
        if all(result is Determination.MET for result in results):
            return Determination.MET
        return Determination.NOT_ASSESSED


@dataclass
class EvidenceRecord:
    evidence_id: str
    title: str
    evidence_class: str
    original_filename: str
    content_sha256: str
    collected_at: str
    collector: str
    acquisition_method: str
    scope_id: str
    classification: str
    retention_expires_at: str
    original_evidence_id: str = ""
    transformations: list[str] = field(default_factory=list)
    chain_of_custody: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path, *, title: str, evidence_class: str, collector: str, scope_id: str, classification: str = "PROPRIETARY", retention_years: int = 6) -> "EvidenceRecord":
        now = datetime.now(timezone.utc)
        return cls(
            evidence_id=f"evd-{uuid4().hex}", title=title, evidence_class=evidence_class,
            original_filename=path.name, content_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            collected_at=now.isoformat(), collector=collector, acquisition_method="FILE_IMPORT",
            scope_id=scope_id, classification=classification,
            retention_expires_at=(now + timedelta(days=365 * retention_years)).isoformat(),
            chain_of_custody=[{"timestamp": now.isoformat(), "actor": collector, "action": "COLLECTED", "hash": hashlib.sha256(path.read_bytes()).hexdigest()}],
        )

    def verify(self, path: Path) -> bool:
        return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == self.content_sha256


def aggregate_assessment_hash(records: list[EvidenceRecord]) -> str:
    canonical = json.dumps(
        [{"evidence_id": item.evidence_id, "sha256": item.content_sha256} for item in sorted(records, key=lambda item: item.evidence_id)],
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def append_audit_entry(path: Path, *, user: str, role: str, action: str, reason: str, assessment_id: str = "", requirement_id: str = "", evidence_id: str = "", result: str = "") -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = ""
    if path.exists():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous_hash = json.loads(lines[-1])["integrity_hash"]
    entry = {"entry_id": f"aud-{uuid4().hex}", "timestamp": datetime.now(timezone.utc).isoformat(), "user": user, "role": role, "action": action, "reason": reason, "assessment_id": assessment_id, "requirement_id": requirement_id, "evidence_id": evidence_id, "result": result, "previous_hash": previous_hash}
    entry["integrity_hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


__all__ = ["PlanningHorizon", "ReadinessState", "Determination", "EvidenceRelationship", "StandardsProfile", "AssessmentObjective", "RequirementAssessment", "EvidenceRecord", "aggregate_assessment_hash", "append_audit_entry"]
