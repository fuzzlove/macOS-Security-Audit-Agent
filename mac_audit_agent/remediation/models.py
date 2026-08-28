from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


UserSkillLevel = Literal["beginner", "analyst", "advanced", "administrator"]
SourceType = Literal[
    "NVD",
    "CISA_KEV",
    "CISA_CPG",
    "MITRE_ATTACK",
    "NIST",
    "DoD_CMMC",
    "NSA_PUBLIC_GUIDANCE",
    "APPLE",
    "PCI_DSS",
    "VENDOR_ADVISORY",
    "INTERNAL_MSAA_RULE",
]
MappingConfidence = Literal["direct", "partial", "supporting_evidence", "manual_review_required", "unknown"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SourceMapping:
    source_type: SourceType
    source_id: str
    source_url: str
    source_version: str = "current public reference"
    mapping_confidence: MappingConfidence = "supporting_evidence"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class POAMItem:
    weakness: str
    affected_asset: str
    recommended_fix: str
    source_standard: str
    owner: str = ""
    target_date: str = ""
    remediation_status: str = "open"
    validation_method: str = ""
    evidence_required: list[str] = field(default_factory=list)
    residual_risk: str = "Residual risk must be reviewed after validation."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RecommendedFix:
    fix_id: str
    finding_id: str
    finding_type: str
    severity: str
    confidence: str
    summary: str
    immediate_action: str
    recommended_fix: str
    further_examination_steps: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    evidence_to_collect: list[str] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    rollback_or_safety_notes: list[str] = field(default_factory=list)
    user_skill_level: UserSkillLevel = "analyst"
    source_mappings: list[SourceMapping] = field(default_factory=list)
    cve_context: dict[str, Any] | None = None
    cisa_kev_context: dict[str, Any] | None = None
    mitre_context: dict[str, Any] | None = None
    apple_context: dict[str, Any] | None = None
    dod_cmmc_context: dict[str, Any] | None = None
    nist_context: dict[str, Any] | None = None
    generated_at: str = field(default_factory=utc_now_iso)
    source_versions: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    possible_new_threat: bool = False
    actor_attribution_status: str = "none"
    suggested_submission_targets: list[str] = field(default_factory=list)
    required_evidence_before_attribution: list[str] = field(default_factory=list)
    false_positive_status: str = "not_reviewed"
    analyst_notes: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    suppress_rule: dict[str, Any] | None = None
    poam: POAMItem | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["source_mappings"] = [item.to_dict() if hasattr(item, "to_dict") else item for item in self.source_mappings]
        payload["poam"] = self.poam.to_dict() if self.poam else None
        return payload


def source_mapping_dicts(mappings: list[SourceMapping]) -> list[dict[str, Any]]:
    return [mapping.to_dict() for mapping in mappings]
