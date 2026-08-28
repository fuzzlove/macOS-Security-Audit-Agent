from __future__ import annotations

from dataclasses import asdict
from typing import Any

from mac_audit_agent.frameworks.assessment_models import PlanningHorizon, StandardsProfile


PROFILES: dict[str, StandardsProfile] = {
    "cmmc_l1_current": StandardsProfile("cmmc_l1_current", "CMMC Level 1 current contractual baseline", PlanningHorizon.CONTRACTUAL_CURRENT, ("cmmc_32_cfr_170", "far_52_204_21", "cmmc_level_1_assessment_guide"), 15, None, "cmmc_32_cfr_170"),
    "cmmc_l2_current": StandardsProfile("cmmc_l2_current", "CMMC Level 2 current contractual baseline", PlanningHorizon.CONTRACTUAL_CURRENT, ("cmmc_32_cfr_170", "dfars_252_204_7012", "nist_sp_800_171_r2", "nist_sp_800_171a_r2", "cmmc_level_2_assessment_guide"), 110, None, "cmmc_32_cfr_170"),
    "cmmc_l3_current": StandardsProfile("cmmc_l3_current", "CMMC Level 3 current contractual baseline", PlanningHorizon.CONTRACTUAL_CURRENT, ("cmmc_32_cfr_170", "nist_sp_800_171_r2", "nist_sp_800_172_2021", "cmmc_level_3_assessment_guide"), 134, None, "cmmc_32_cfr_170"),
    "nist_171_r3_future": StandardsProfile("nist_171_r3_future", "NIST SP 800-171 Rev. 3 future readiness", PlanningHorizon.FINAL_FUTURE_READINESS, ("nist_sp_800_171_r3", "nist_sp_800_171a_r3"), 0, None),
    "nist_172_r3_future": StandardsProfile("nist_172_r3_future", "NIST SP 800-172 Rev. 3 future readiness", PlanningHorizon.FINAL_FUTURE_READINESS, ("nist_sp_800_172_r3", "nist_sp_800_172a_r3"), 0, None),
}


def validate_profile_isolation(profile_id: str, *, requested_for_current_score: bool = False) -> dict[str, Any]:
    profile = PROFILES[profile_id]
    allowed = not requested_for_current_score or profile.may_drive_current_score()
    return {"profile": asdict(profile), "allowed": allowed, "error_code": "" if allowed else "STD003", "message": "Profile is isolated from current contractual scoring." if not allowed else "Profile selection is valid."}


def validate_catalog(profile_id: str, requirement_ids: list[str], objective_parent_ids: list[str]) -> dict[str, Any]:
    profile = PROFILES[profile_id]
    duplicates = sorted({item for item in requirement_ids if requirement_ids.count(item) > 1})
    orphaned = sorted(set(objective_parent_ids) - set(requirement_ids))
    missing_count = max(0, profile.expected_requirement_count - len(set(requirement_ids)))
    complete = not duplicates and not orphaned and missing_count == 0 and len(set(requirement_ids)) == profile.expected_requirement_count
    return {"profile_id": profile_id, "expected_requirements": profile.expected_requirement_count, "actual_requirements": len(set(requirement_ids)), "missing_requirement_count": missing_count, "duplicate_requirements": duplicates, "orphaned_objective_parents": orphaned, "complete": complete, "status": "PASS" if complete else "BLOCKER", "error_code": "" if complete else "STD004"}


__all__ = ["PROFILES", "validate_profile_isolation", "validate_catalog"]
