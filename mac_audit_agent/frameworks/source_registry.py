from __future__ import annotations

import hashlib
import json
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OFFICIAL_SOURCE_DOMAINS = (
    "ecfr.gov",
    "dodcio.defense.gov",
    "defense.gov",
    "acq.osd.mil",
    "cisa.gov",
    "nist.gov",
    "csrc.nist.gov",
    "nvlpubs.nist.gov",
    "nsa.gov",
    "pcisecuritystandards.org",
    "attack.mitre.org",
    "mitre.org",
)


@dataclass(frozen=True)
class OfficialFrameworkSource:
    source_id: str
    framework: str
    title: str
    issuing_authority: str
    source_url: str
    version: str
    publication_date: str
    retrieved_at: str
    hash_sha256: str = ""
    local_cache_path: str = ""
    normative: bool = True
    source_type: str = "government_standard"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["cache_path"] = self.local_cache_path
        payload["source_status"] = source_status(self)
        payload["cache_status"] = cache_status(self)
        payload["official_domain"] = is_official_source_url(self.source_url)
        return payload


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_cache_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "framework_sources"


def official_framework_sources(*, retrieved_at: str | None = None, cache_dir: Path | None = None) -> list[OfficialFrameworkSource]:
    retrieved = retrieved_at or utc_now_iso()
    cache = cache_dir or default_cache_dir()
    specs = [
        ("cmmc_32_cfr_170", "CMMC", "32 CFR Part 170, Cybersecurity Maturity Model Certification Program", "Electronic Code of Federal Regulations", "https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-M/part-170", "32 CFR Part 170 current", "", True, "government_standard", "Normative CMMC program rule."),
        ("cmmc_dodcio_resources", "CMMC", "DoD CIO CMMC Resources & Documentation", "Department of Defense Chief Information Officer", "https://dodcio.defense.gov/CMMC/Documentation/", "Current CMMC documentation portal", "", True, "government_guidance", "Official CMMC resources and documentation landing page."),
        ("cmmc_level_1_assessment_guide", "CMMC", "CMMC Level 1 Assessment Guide", "Department of Defense Chief Information Officer", "https://dodcio.defense.gov/CMMC/Documentation/", "Current official guide if published", "", True, "government_guidance", "Use official DoD guide from the documentation portal when available; cached mode must label source status."),
        ("cmmc_level_2_assessment_guide", "CMMC", "CMMC Level 2 Assessment Guide", "Department of Defense Chief Information Officer", "https://dodcio.defense.gov/CMMC/Documentation/", "Current official guide if published", "", True, "government_guidance", "Use official DoD guide from the documentation portal when available; CMMC L2 maps to NIST SP 800-171 requirements."),
        ("cmmc_level_3_assessment_guide", "CMMC", "CMMC Level 3 Assessment Guide", "Department of Defense Chief Information Officer", "https://dodcio.defense.gov/CMMC/Documentation/", "Current official guide if published", "", True, "government_guidance", "Use official DoD guide from the documentation portal when available; advanced requirements may reference NIST SP 800-172."),
        ("cmmc_nist_alignment", "CMMC", "CMMC and NIST alignment documentation", "Department of Defense Chief Information Officer", "https://dodcio.defense.gov/CMMC/Documentation/", "Current official alignment references", "", True, "government_guidance", "Do not use vendor crosswalks as authoritative mappings."),
        ("nist_sp_800_171_r2", "NIST", "NIST SP 800-171 Rev. 2", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final", "Revision 2, update as of 2021-01-28; withdrawn/superseded", "2020-02", True, "government_standard", "NIST states the PDF is the authoritative source for Rev. 2 CUI security requirements."),
        ("nist_sp_800_171_r3", "NIST", "NIST SP 800-171 Rev. 3", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/171/r3/final", "Revision 3 final", "2024-05", True, "government_standard", "Current final revision for CUI security requirements."),
        ("nist_sp_800_171a", "NIST", "NIST SP 800-171A", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/171/a/final", "Final", "2018-06", True, "government_standard", "Assessment procedures for SP 800-171 requirements."),
        ("nist_sp_800_172", "NIST", "NIST SP 800-172", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/172/final", "Final", "2021-02", True, "government_standard", "Enhanced security requirements for protecting CUI."),
        ("nist_sp_800_172a", "NIST", "NIST SP 800-172A", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/172/a/final", "Final", "2022-03", True, "government_standard", "Assessment procedures for enhanced CUI requirements where applicable."),
        ("nist_csf_2_0", "NIST", "NIST Cybersecurity Framework 2.0", "National Institute of Standards and Technology", "https://www.nist.gov/cyberframework", "2.0", "2024-02", True, "government_standard", "NIST CSF 2.0 framework reference."),
        ("nist_sp_800_53_r5", "NIST", "NIST SP 800-53 Rev. 5", "National Institute of Standards and Technology", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final", "Revision 5, update 1", "2020-09", True, "government_standard", "Security and privacy controls catalog."),
        ("cisa_cpg_2_0", "CISA", "Cybersecurity Performance Goals", "Cybersecurity and Infrastructure Security Agency", "https://www.cisa.gov/cybersecurity-performance-goals", "CPG 2.0 current public guidance", "", False, "government_guidance", "Public CISA baseline practices for cybersecurity outcomes."),
        ("cisa_kev_catalog", "CISA", "Known Exploited Vulnerabilities Catalog", "Cybersecurity and Infrastructure Security Agency", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Current catalog", "", False, "government_guidance", "Use for vulnerability exposure context, not as a local compliance claim."),
        ("cisa_secure_by_design", "CISA", "Secure by Design guidance", "Cybersecurity and Infrastructure Security Agency", "https://www.cisa.gov/securebydesign", "Current public guidance", "", False, "government_guidance", "Reference guidance for secure-by-design framing and defensive defaults."),
        ("nsa_cybersecurity", "NSA", "NSA Cybersecurity Advisories and Guidance", "National Security Agency", "https://www.nsa.gov/Cybersecurity/", "Current public cybersecurity portal", "", False, "government_guidance", "Public NSA cybersecurity guidance and advisories reference."),
        ("nsa_cybersecurity_advisories", "NSA", "NSA Cybersecurity Advisories", "National Security Agency", "https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/", "Current public advisories", "", False, "government_guidance", "Use as public guidance alignment only; no endorsement or approval implied."),
        ("pci_dss_4_0_1", "PCI", "PCI DSS v4.0.1", "PCI Security Standards Council", "https://www.pcisecuritystandards.org/document_library/", "4.0.1", "2024-06", True, "industry_standard", "Industry payment-card security standard; not a government framework."),
        ("pci_dss_roc_aoc_templates", "PCI", "PCI DSS ROC/AOC Templates", "PCI Security Standards Council", "https://www.pcisecuritystandards.org/document_library/", "Current templates", "", False, "public_reference", "Reference only for report/evidence structure where payment-card relevance exists."),
        ("mitre_attack_enterprise", "MITRE", "MITRE ATT&CK Enterprise Matrix", "MITRE", "https://attack.mitre.org/matrices/enterprise/", "Current public matrix", "", False, "public_reference", "Public technique context reference; not a compliance framework."),
        ("mitre_attack_macos", "MITRE", "MITRE ATT&CK macOS Platform Techniques", "MITRE", "https://attack.mitre.org/platforms/macOS/", "Current public platform reference", "", False, "public_reference", "Use for macOS technique context and defensive mapping only."),
        ("dfars_252_204_7012", "DFARS", "DFARS 252.204-7012", "Electronic Code of Federal Regulations", "https://www.ecfr.gov/current/title-48/chapter-2/subchapter-H/part-252/subpart-252.2/section-252.204-7012", "Current eCFR", "", True, "government_standard", "Safeguarding covered defense information and cyber incident reporting clause."),
        ("dfars_252_204_7020", "DFARS", "DFARS 252.204-7020", "Electronic Code of Federal Regulations", "https://www.ecfr.gov/current/title-48/chapter-2/subchapter-H/part-252/subpart-252.2/section-252.204-7020", "Current eCFR", "", True, "government_standard", "NIST SP 800-171 DoD assessment requirements clause."),
        ("dfars_252_204_7021", "DFARS", "DFARS 252.204-7021", "Electronic Code of Federal Regulations", "https://www.ecfr.gov/current/title-48/chapter-2/subchapter-H/part-252/subpart-252.2/section-252.204-7021", "Current eCFR", "", True, "government_standard", "CMMC requirements clause where applicable/current."),
        ("dod_assessment_methodology", "DoD", "DoD Assessment Methodology references", "Department of Defense", "https://dodcio.defense.gov/CMMC/Documentation/", "Current official references", "", False, "government_guidance", "Use official DoD-published methodology references only."),
    ]
    return [
        OfficialFrameworkSource(
            source_id=source_id,
            framework=framework,
            title=title,
            issuing_authority=authority,
            source_url=url,
            version=version,
            publication_date=publication_date,
            retrieved_at=retrieved,
            local_cache_path=str(cache / f"{source_id}.json"),
            normative=normative,
            source_type=source_type,
            notes=notes,
        )
        for source_id, framework, title, authority, url, version, publication_date, normative, source_type, notes in specs
    ]


def sources_by_id() -> dict[str, OfficialFrameworkSource]:
    return {source.source_id: source for source in official_framework_sources()}


def is_official_source_url(url: str) -> bool:
    lowered = url.lower()
    return lowered.startswith("https://") and any(domain in lowered for domain in OFFICIAL_SOURCE_DOMAINS)


def source_status(source: OfficialFrameworkSource) -> str:
    if not is_official_source_url(source.source_url):
        return "untrusted_source"
    cache = Path(source.local_cache_path).expanduser() if source.local_cache_path else None
    if cache and cache.exists():
        return "cached"
    return "registered"


def cache_status(source: OfficialFrameworkSource) -> str:
    if not source.local_cache_path:
        return "not_configured"
    cache = Path(source.local_cache_path).expanduser()
    return "cached" if cache.exists() else "not_cached"


def validate_sources(*, fetch: bool = False, cache_dir: Path | None = None, timeout: int = 10) -> dict[str, Any]:
    sources = official_framework_sources(cache_dir=cache_dir)
    results = []
    for source in sources:
        status = source_status(source)
        error = ""
        hash_sha256 = source.hash_sha256
        if fetch:
            try:
                payload = _fetch_source(source.source_url, timeout=timeout)
                hash_sha256 = hashlib.sha256(payload).hexdigest()
                if source.local_cache_path:
                    path = Path(source.local_cache_path).expanduser()
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                status = "current"
            except Exception as exc:  # noqa: BLE001
                status = "stale_or_unavailable"
                error = str(exc)
        item = source.to_dict()
        item.update({"source_status": status, "hash_sha256": hash_sha256, "error": error})
        results.append(item)
    return {
        "validated_at": utc_now_iso(),
        "fetch_attempted": fetch,
        "sources": results,
        "warnings": [item for item in results if item["source_status"] in {"stale_or_unavailable", "untrusted_source"}],
    }


def _fetch_source(url: str, *, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "MSAA framework source validator"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - source registry only allows official HTTPS URLs.
        return response.read()


def write_source_manifest(path: Path, *, fetch: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(validate_sources(fetch=fetch), indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = [
    "OfficialFrameworkSource",
    "OFFICIAL_SOURCE_DOMAINS",
    "official_framework_sources",
    "sources_by_id",
    "is_official_source_url",
    "source_status",
    "cache_status",
    "validate_sources",
    "write_source_manifest",
]
