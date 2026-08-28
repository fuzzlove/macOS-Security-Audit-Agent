from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.education.accessibility import AccessibilityImpactReview
from mac_audit_agent.education.applicability import completion_blockers, evaluate_applicability
from mac_audit_agent.education.containment import ActionNamespace, ContainmentPlan
from mac_audit_agent.education.models import AccommodationDescriptor, AuthorityType, DistrictAsset, DistrictProfile
from mac_audit_agent.education.privacy import require_privacy_exception


def asset(**changes):
    values = dict(asset_id="synthetic-asset", name="Synthetic AAC gateway", asset_type="service", owner="district-it", criticality="critical", data_classification="sensitive", accommodations=(AccommodationDescriptor.AAC_SERVICE_REQUIRED,), emergency_service=True)
    values.update(changes)
    return DistrictAsset(**values)


def test_layered_applicability_does_not_turn_voluntary_guidance_into_law():
    decisions = evaluate_applicability(DistrictProfile("Synthetic District", jurisdiction="OR", receives_ed_funds=True, erate_or_covered_federal_support=False))
    cisa = next(x for x in decisions if x.profile_id == "CISA_K12_BASELINE")
    cipa = next(x for x in decisions if x.profile_id == "CIPA")
    assert cisa.authority_type is AuthorityType.VOLUNTARY_HIGH_PRIORITY_BASELINE
    assert cipa.applicable is False


def test_unresolved_jurisdiction_blocks_complete_result():
    assert "JURISDICTION_OVERLAY" in completion_blockers(DistrictProfile("Synthetic District"))


def test_asset_rejects_diagnosis_storage():
    with pytest.raises(ValueError, match="EDU-PRIV001"):
        asset(metadata={"diagnosis": "must never be stored here"})


def test_containment_blocks_assistive_and_emergency_services():
    plan = ContainmentPlan("act-1", ActionNamespace.CYBER_CONTAINMENT, "isolate endpoint", asset(), datetime.now(timezone.utc) + timedelta(minutes=15), "restore network policy", ("approver-1",))
    review = AccessibilityImpactReview("a11y-reviewer", (AccommodationDescriptor.AAC_SERVICE_REQUIRED,), True, reversible=True, consulted_accessibility_role=True)
    with pytest.raises(PermissionError, match="EDU-A11Y001"):
        plan.authorize(review)


def test_high_impact_requires_two_people_and_expiration():
    safe_asset = asset(accommodations=(), emergency_service=False)
    plan = ContainmentPlan("act-2", ActionNamespace.CYBER_CONTAINMENT, "restrict network zone", safe_asset, datetime.now(timezone.utc) + timedelta(minutes=15), "restore ACL", ("one",), high_impact=True)
    review = AccessibilityImpactReview("reviewer", reversible=True, consulted_accessibility_role=True)
    with pytest.raises(PermissionError, match="EDU-SAFE004"):
        plan.authorize(review)


def test_physical_emergency_action_cannot_be_automated():
    plan = ContainmentPlan("act-3", ActionNamespace.PHYSICAL_EMERGENCY_ACTION, "lock doors", asset(), datetime.now(timezone.utc) + timedelta(minutes=5), "not applicable", ("one", "two"), high_impact=True)
    with pytest.raises(PermissionError, match="EDU-SAFE001"):
        plan.authorize(AccessibilityImpactReview("reviewer", reversible=True, consulted_accessibility_role=True))


def test_student_surveillance_is_default_deny():
    with pytest.raises(PermissionError, match="EDU-PRIV002"):
        require_privacy_exception("facial_recognition", {})
