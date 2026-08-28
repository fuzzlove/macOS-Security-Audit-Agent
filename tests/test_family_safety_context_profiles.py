from mac_audit_agent.family_safety import FamilySafetyAuditor
from mac_audit_agent.family_safety.profiles import canonical_family_safety_profiles
from mac_audit_agent.family_safety.recommendation_engine import _profile_for_answers
from mac_audit_agent.family_safety.wizard_questions import canonical_family_safety_questions
from mac_audit_agent.ui.family_safety_panel import PROFILE_OPTIONS


def test_quick_audit_exposes_critical_asset_use_contexts():
    expected = {"Security Research Device", "Government Asset", "Doctor's Device", "Nurse's Workstation", "Health Device", "Lawyer's Device / Legal Asset"}
    assert expected.issubset(set(PROFILE_OPTIONS))
    auditor = FamilySafetyAuditor()
    for label in expected:
        result = auditor.recommendations_for_profile(label)
        assert result["profile"] == [label]
        assert len(result["recommendations"]) >= 2


def test_detailed_wizard_maps_context_without_claiming_status():
    cases = {
        "Security research device": "security_research_device",
        "Government asset": "government_asset",
        "Doctor / clinician device": "clinical_health_device",
        "Nurse workstation": "clinical_health_device",
        "Health device": "clinical_health_device",
        "Lawyer / legal asset": "legal_confidentiality_asset",
    }
    primary = next(item for item in canonical_family_safety_questions() if item.question_id == "primary_user")
    for label, expected_profile in cases.items():
        assert label in primary.options
        profile_id, reasons, _confidence = _profile_for_answers({"primary_user": label})
        assert profile_id == expected_profile
        assert any("does not establish" in reason for reason in reasons)


def test_context_profiles_include_privacy_and_manual_review_boundaries():
    profiles = {profile.profile_id: profile for profile in canonical_family_safety_profiles()}
    for profile_id in ("security_research_device", "government_asset", "clinical_health_device", "legal_confidentiality_asset"):
        profile = profiles[profile_id]
        assert profile.manual_review_items
        assert profile.privacy_notes
        assert profile.revert_supported is True
    assert any("patient" in note.lower() for note in profiles["clinical_health_device"].privacy_notes)
    assert any("client" in note.lower() for note in profiles["legal_confidentiality_asset"].privacy_notes)
