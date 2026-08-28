from __future__ import annotations

from typing import Any

from .vulnerability_db import VulnerabilityKnowledge


def build_explanation(
    *,
    cwe: str,
    title: str,
    detection_reason: str,
    knowledge: VulnerabilityKnowledge,
) -> dict[str, Any]:
    entry = knowledge.cwes[cwe]
    remediation = knowledge.remediations.get(cwe, {})
    explanation = (
        f"{entry['definition']} MSAA flagged this occurrence because {detection_reason} "
        f"Static analysis identifies a review candidate, not proof that attacker-controlled data reaches the operation."
    )
    return {
        "description": entry["definition"],
        "analyst_explanation": explanation,
        "impact": dict(entry["impact"]),
        "exploitability": dict(entry["exploitability"]),
        "remediation": remediation,
        "references": tuple(entry["references"]),
        "mitre_attack": knowledge.mitre.get(cwe, ()),
        "compliance": {
            "nist_ssdf": tuple(entry.get("nist_ssdf", ())),
            "nist_csf": tuple(entry.get("nist_csf", ())),
            "owasp": tuple(entry.get("owasp", ())),
        },
    }


__all__ = ["build_explanation"]
