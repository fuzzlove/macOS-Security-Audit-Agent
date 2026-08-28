from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from mac_audit_agent.compat.enum import StrEnum
from pathlib import Path
from typing import Any


class ConformanceStatus(StrEnum):
    CONFORMANT = "CONFORMANT"
    CONFORMANT_WITH_LIMITATIONS = "CONFORMANT_WITH_LIMITATIONS"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


REQUIRED_HEADER_FIELDS = (
    "report_title", "organization", "assessment_scope", "contract_or_solicitation",
    "assessment_type", "cmmc_level", "standards_profile", "standard_revisions",
    "guide_versions", "rule_set_version", "content_pack_sha256", "source_retrieval_dates",
    "generated_at", "timezone", "evidence_cutoff_date", "assessment_period", "analyst",
    "reviewer", "application_version", "build_id", "data_source_summary",
    "scope_limitations", "evidence_limitations", "unverified_assumptions", "disclaimer",
)

UNSUPPORTED_CLAIMS = ("cmmc certified", "nist compliant", "dod approved", "guaranteed to pass", "official assessment result", "fully compliant")


@dataclass
class ReportConformanceResult:
    status: ConformanceStatus
    checklist: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_report(payload: dict[str, Any], *, expected_requirements: int, expected_objectives: int | None) -> ReportConformanceResult:
    header = payload.get("header", {})
    missing_header = [field for field in REQUIRED_HEADER_FIELDS if field not in header or header[field] in (None, "", [])]
    requirements = payload.get("requirements", []) or []
    objectives = payload.get("objectives", []) or []
    requirement_ids = [str(item.get("requirement_id", "")) for item in requirements]
    objective_ids = [str(item.get("objective_id", "")) for item in objectives]
    text = json.dumps(payload, sort_keys=True).lower()
    false_claims = [claim for claim in UNSUPPORTED_CLAIMS if claim in text]
    errors: list[str] = []
    if false_claims: errors.append(f"unsupported claims: {', '.join(false_claims)}")
    if len(set(requirement_ids)) != expected_requirements: errors.append(f"requirement coverage {len(set(requirement_ids))}/{expected_requirements}")
    if expected_objectives is not None and len(set(objective_ids)) != expected_objectives: errors.append(f"objective coverage {len(set(objective_ids))}/{expected_objectives}")
    orphaned = sorted({str(item.get("requirement_id", "")) for item in objectives} - set(requirement_ids))
    if orphaned: errors.append(f"orphaned objectives: {orphaned}")
    missing_signoffs = [item.get("requirement_id") for item in requirements if item.get("determination") == "MET" and not item.get("reviewer_signoff")]
    if missing_signoffs: errors.append("MET requirements missing reviewer signoff")
    status = ConformanceStatus.INVALID if false_claims or missing_signoffs else ConformanceStatus.INCOMPLETE if errors or missing_header else ConformanceStatus.CONFORMANT_WITH_LIMITATIONS if header.get("scope_limitations") or header.get("evidence_limitations") else ConformanceStatus.CONFORMANT
    checklist = {
        "source_integrity": {"versions_recorded": bool(header.get("standard_revisions")), "hashes_recorded": bool(header.get("content_pack_sha256")), "profiles_separated": bool(payload.get("profiles_separated"))},
        "scope": {"documented": bool(header.get("assessment_scope")), "unresolved_questions": payload.get("unresolved_scope_questions", [])},
        "catalog": {"expected_requirements": expected_requirements, "actual_requirements": len(set(requirement_ids)), "expected_objectives": expected_objectives, "actual_objectives": len(set(objective_ids)), "duplicates": len(requirement_ids) != len(set(requirement_ids)), "orphaned_objectives": orphaned},
        "methods": payload.get("method_completeness", {}),
        "evidence": payload.get("evidence_completeness", {}),
        "determinations": {"reviewer_signoffs_missing": missing_signoffs},
        "scoring": payload.get("scoring_integrity", {}),
        "reporting": {"missing_header_fields": missing_header, "unsupported_claims": false_claims, "disclaimer_present": bool(header.get("disclaimer"))},
    }
    return ReportConformanceResult(status, checklist, errors, list(header.get("scope_limitations", [])) + list(header.get("evidence_limitations", [])))


def write_reproducible_json(payload: dict[str, Any], path: Path) -> dict[str, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(content, encoding="utf-8")
    return {"path": str(path), "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}


__all__ = ["ConformanceStatus", "ReportConformanceResult", "REQUIRED_HEADER_FIELDS", "evaluate_report", "write_reproducible_json"]
