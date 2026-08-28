from __future__ import annotations

from dataclasses import dataclass

from mac_audit_agent.frameworks.assessment_models import Determination, RequirementAssessment
from mac_audit_agent.frameworks.standards_profiles import PROFILES


@dataclass(frozen=True)
class ScoreResult:
    profile_id: str
    status: str
    score: int | None
    maximum: int | None
    explanation: str
    error_code: str = ""


def score_assessment(profile_id: str, requirements: list[RequirementAssessment], *, official_weights: dict[str, int] | None = None) -> ScoreResult:
    profile = PROFILES[profile_id]
    if profile.horizon.value != "CONTRACTUAL_CURRENT":
        return ScoreResult(profile_id, "NOT_APPLICABLE", None, None, "Future-readiness profiles never alter the current contractual CMMC score.", "STD003")
    if len(requirements) != profile.expected_requirement_count:
        return ScoreResult(profile_id, "INVALID", None, None, f"Catalog incomplete: expected {profile.expected_requirement_count}, received {len(requirements)}.", "STD004")
    if not profile.may_drive_current_score():
        return ScoreResult(profile_id, "NOT_APPLICABLE", None, None, "The contractual profile is not scoring-active until its complete content pack is verified and explicitly approved.", "STD005")
    determinations = {item.requirement_id: item.determination() for item in requirements}
    if profile_id == "cmmc_l1_current":
        ready = all(value is Determination.MET for value in determinations.values())
        return ScoreResult(profile_id, "FINAL_READY" if ready else "INCOMPLETE", None, None, "Level 1 has no invented numeric score and permits no POA&M.")
    if not official_weights or set(official_weights) != set(determinations):
        return ScoreResult(profile_id, "INVALID", None, 110 if profile_id == "cmmc_l2_current" else None, "Exact official requirement weights are required; generic percentages and invented partial credit are prohibited.", "SCR001")
    score = 110
    arithmetic: list[str] = ["start=110"]
    for requirement_id, result in sorted(determinations.items()):
        if result is not Determination.MET:
            deduction = official_weights[requirement_id]
            score -= deduction
            arithmetic.append(f"{requirement_id}:-{deduction}")
    return ScoreResult(profile_id, "CALCULATED", score, 110, "; ".join(arithmetic))


__all__ = ["ScoreResult", "score_assessment"]
