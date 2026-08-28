from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


Automation = Literal["validated_rule_staging", "vulnerability_correlation", "human_review_only"]


@dataclass(frozen=True)
class RansomwareAdvisorySource:
    source_id: str
    organization: str
    official_url: str
    automation: Automation
    purpose: str
    limitation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


RANSOMWARE_ADVISORY_SOURCES = (
    RansomwareAdvisorySource(
        "cisa_kev",
        "CISA",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "vulnerability_correlation",
        "Prioritize locally observed exposure, including the catalog's known-ransomware-campaign field.",
        "KEV presence is not proof of exploitation and does not itself supply a macOS detection rule.",
    ),
    RansomwareAdvisorySource(
        "cisa_stopransomware_rules",
        "CISA",
        "https://www.cisa.gov/stopransomware",
        "validated_rule_staging",
        "Stage explicitly named YARA rules from allowlisted CISA advisories for compilation and analyst approval.",
        "Narrative text is never converted automatically into a rule; staged rules are inactive until named approval.",
    ),
    RansomwareAdvisorySource(
        "nist_nvd",
        "NIST NVD",
        "https://nvd.nist.gov/developers/vulnerabilities",
        "vulnerability_correlation",
        "Validate CVE records, affected-product metadata, versions, provenance, and retrieval dates.",
        "NVD vulnerability metadata is not a malware signature and an affected version is not evidence of ransomware execution.",
    ),
    RansomwareAdvisorySource(
        "fbi_ransomware",
        "FBI",
        "https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams/ransomware",
        "human_review_only",
        "Give analysts current response, reporting, and joint StopRansomware advisory context.",
        "The public page is guidance, not an authenticated machine-readable detection feed.",
    ),
    RansomwareAdvisorySource(
        "dod_cyber_exchange",
        "DoD Cyber Exchange",
        "https://public.cyber.mil/",
        "human_review_only",
        "Support authorized analysts reviewing applicable public DoD guidance.",
        "No universal public DoD ransomware rule feed is assumed; mission-specific sources require separate authorization and validation.",
    ),
    RansomwareAdvisorySource(
        "interpol_ransomware",
        "INTERPOL",
        "https://www.interpol.int/Crimes/Cybercrime/Ransomware",
        "human_review_only",
        "Provide international awareness and appropriate coordination context.",
        "INTERPOL information does not authorize access, certify MSAA, or constitute an endpoint indicator feed.",
    ),
)


def advisory_source_status() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "sources": [source.to_dict() for source in RANSOMWARE_ADVISORY_SOURCES],
        "automatic_rule_generation_from_narrative": False,
        "human_approval_required_before_rule_activation": True,
        "network_retrieval_by_privileged_sensor": False,
        "government_approval_or_endorsement_claimed": False,
    }


__all__ = ["RANSOMWARE_ADVISORY_SOURCES", "RansomwareAdvisorySource", "advisory_source_status"]
