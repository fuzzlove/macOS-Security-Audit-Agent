# Standards Source Registry

Generated: 2026-07-06

MSAA uses `mac_audit_agent/frameworks/source_registry.py` as the source-of-truth registry for framework and guidance references used in readiness mapping.

## Source Types

- `government_standard`: normative or standards-oriented government source.
- `government_guidance`: public government guidance or reference material.
- `industry_standard`: non-government industry standard.
- `public_reference`: supporting public reference material such as technique context, templates, or report structures.

## Included Source Families

- NIST: CSF 2.0, SP 800-53 Rev. 5, SP 800-171 Rev. 2 / Rev. 3, SP 800-171A, SP 800-172, SP 800-172A.
- CISA: Cybersecurity Performance Goals, Known Exploited Vulnerabilities Catalog, Secure by Design guidance.
- DoD/CMMC/DFARS: 32 CFR Part 170, DoD CIO CMMC documentation, assessment guide references, DFARS 252.204-7012 / 7020 / 7021.
- NSA: public cybersecurity advisories and guidance portal references.
- PCI SSC: PCI DSS v4.0.1 and ROC/AOC reference templates where payment-card relevance exists.
- MITRE: ATT&CK Enterprise and macOS technique references for defensive context.

## Source Handling Rules

- Prefer official `.gov`, `nist.gov`, `csrc.nist.gov`, `cisa.gov`, `dodcio.defense.gov`, `nsa.gov`, `ecfr.gov`, and `pcisecuritystandards.org` sources.
- Do not use vendor blogs as authoritative framework sources.
- Record version, retrieval timestamp, source type, cache status, issuing authority, and URL.
- If cached source validation is stale or unavailable, reports must label it as stale or unavailable.
- PCI DSS is an industry payment-card security standard, not a government framework.

## Disclaimer

MSAA is an independent project by Liquidsky Network Security. References to NIST, CISA, DoD, NSA, PCI SSC, MITRE, or other standards bodies are for standards mapping, source attribution, and public guidance alignment only. They do not imply endorsement, sponsorship, certification, or approval.
