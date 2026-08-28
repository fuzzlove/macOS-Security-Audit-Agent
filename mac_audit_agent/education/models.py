from __future__ import annotations

from dataclasses import dataclass, field
from mac_audit_agent.compat.enum import StrEnum
from typing import Any


class AuthorityType(StrEnum):
    MANDATORY_FEDERAL = "MANDATORY_FEDERAL"
    CONDITIONAL_FEDERAL = "CONDITIONAL_FEDERAL"
    FEDERAL_CONTRACT_OR_GRANT = "FEDERAL_CONTRACT_OR_GRANT"
    STATE_REQUIRED = "STATE_REQUIRED"
    TERRITORIAL_REQUIRED = "TERRITORIAL_REQUIRED"
    TRIBAL_OR_BIE_REQUIRED = "TRIBAL_OR_BIE_REQUIRED"
    LOCAL_POLICY_REQUIRED = "LOCAL_POLICY_REQUIRED"
    INSURANCE_REQUIRED = "INSURANCE_REQUIRED"
    VOLUNTARY_HIGH_PRIORITY_BASELINE = "VOLUNTARY_HIGH_PRIORITY_BASELINE"
    SUPPORTING_BEST_PRACTICE = "SUPPORTING_BEST_PRACTICE"
    FUTURE_WATCH = "FUTURE_WATCH"
    INFORMATIONAL_MAPPING = "INFORMATIONAL_MAPPING"


class AccommodationDescriptor(StrEnum):
    SCREEN_READER_REQUIRED = "SCREEN_READER_REQUIRED"
    AAC_SERVICE_REQUIRED = "AAC_SERVICE_REQUIRED"
    CAPTIONING_REQUIRED = "CAPTIONING_REQUIRED"
    TEXT_TO_SPEECH_REQUIRED = "TEXT_TO_SPEECH_REQUIRED"
    SPEECH_TO_TEXT_REQUIRED = "SPEECH_TO_TEXT_REQUIRED"
    SWITCH_CONTROL_REQUIRED = "SWITCH_CONTROL_REQUIRED"
    BRAILLE_DISPLAY_REQUIRED = "BRAILLE_DISPLAY_REQUIRED"
    MAGNIFICATION_REQUIRED = "MAGNIFICATION_REQUIRED"
    ALTERNATIVE_INPUT_REQUIRED = "ALTERNATIVE_INPUT_REQUIRED"
    EXTENDED_SESSION_TIME_REQUIRED = "EXTENDED_SESSION_TIME_REQUIRED"
    LOW_BANDWIDTH_REQUIRED = "LOW_BANDWIDTH_REQUIRED"
    OFFLINE_ACCESS_REQUIRED = "OFFLINE_ACCESS_REQUIRED"
    REDUCED_MOTION_REQUIRED = "REDUCED_MOTION_REQUIRED"
    MULTILINGUAL_ACCESS_REQUIRED = "MULTILINGUAL_ACCESS_REQUIRED"


@dataclass(frozen=True)
class DistrictProfile:
    name: str
    jurisdiction: str | None = None
    receives_ed_funds: bool | None = None
    erate_or_covered_federal_support: bool | None = None
    fcc_pilot_participant: bool | None = None
    federal_contract_invokes_nist_171: bool | None = None
    public_entity_population: int | None = None
    tribal_or_bie: bool = False
    unresolved_questions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApplicabilityDecision:
    profile_id: str
    authority_type: AuthorityType
    applicable: bool | None
    rationale: str
    source_ids: tuple[str, ...]
    legal_review_required: bool = True


@dataclass(frozen=True)
class DistrictAsset:
    asset_id: str
    name: str
    asset_type: str
    owner: str
    criticality: str
    data_classification: str
    accommodations: tuple[AccommodationDescriptor, ...] = ()
    emergency_service: bool = False
    educational_continuity_impact: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        forbidden = {"diagnosis", "disability", "iep", "section_504", "medical_condition"}
        found = forbidden.intersection(k.lower() for k in self.metadata)
        if found:
            raise ValueError(
                "[EDU-PRIV001] Diagnosis or disability details are prohibited in security asset metadata; "
                f"detected keys={sorted(found)}. Record only an AccommodationDescriptor."
            )
