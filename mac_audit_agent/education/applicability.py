from __future__ import annotations

from .models import ApplicabilityDecision, AuthorityType, DistrictProfile


def evaluate_applicability(profile: DistrictProfile) -> tuple[ApplicabilityDecision, ...]:
    """Return layered decisions; ``None`` means unresolved and blocks completion."""
    state_known = bool(profile.jurisdiction)
    return (
        ApplicabilityDecision(
            "FERPA",
            AuthorityType.MANDATORY_FEDERAL,
            profile.receives_ed_funds,
            "Applies to an educational agency or institution receiving applicable U.S. Department of Education funds; it is not a prescriptive security-control catalog.",
            ("ED-FERPA",),
        ),
        ApplicabilityDecision(
            "CIPA",
            AuthorityType.CONDITIONAL_FEDERAL,
            profile.erate_or_covered_federal_support,
            "Conditional on the covered E-Rate or specified federal support relationship; it does not authorize unlimited surveillance.",
            ("FCC-CIPA",),
        ),
        ApplicabilityDecision(
            "FCC_CYBERSECURITY_PILOT",
            AuthorityType.CONDITIONAL_FEDERAL,
            profile.fcc_pilot_participant,
            "The temporary FCC pilot is separate from ordinary E-Rate and applies only to participating entities.",
            ("FCC-CYBER-PILOT",),
        ),
        ApplicabilityDecision(
            "NIST_SP_800_171",
            AuthorityType.FEDERAL_CONTRACT_OR_GRANT,
            profile.federal_contract_invokes_nist_171,
            "Applies only when a contract, grant, or CUI relationship invokes it; it is not a universal district mandate.",
            ("NIST-800-171",),
        ),
        ApplicabilityDecision(
            "JURISDICTION_OVERLAY",
            AuthorityType.TRIBAL_OR_BIE_REQUIRED if profile.tribal_or_bie else AuthorityType.STATE_REQUIRED,
            None if not state_known else True,
            "A verified jurisdiction-specific legal content pack and human legal review are required before a final result.",
            ("JURISDICTION-OFFICIAL-SOURCES",),
        ),
        ApplicabilityDecision(
            "CISA_K12_BASELINE",
            AuthorityType.VOLUNTARY_HIGH_PRIORITY_BASELINE,
            True,
            "CISA's K-12 recommendations are a voluntary high-priority readiness baseline unless separately adopted by authority.",
            ("CISA-K12-POF",),
            legal_review_required=False,
        ),
    )


def completion_blockers(profile: DistrictProfile) -> tuple[str, ...]:
    blockers = list(profile.unresolved_questions)
    blockers.extend(d.profile_id for d in evaluate_applicability(profile) if d.applicable is None)
    return tuple(dict.fromkeys(blockers))
