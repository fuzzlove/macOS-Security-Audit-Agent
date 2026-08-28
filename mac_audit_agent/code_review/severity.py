from __future__ import annotations

import re

CVSS_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"
)


def severity_for_score(score: float) -> str:
    if not 0 <= score <= 10:
        raise ValueError("CVSS score must be between 0.0 and 10.0")
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def validate_cvss(score: float, vector: str) -> None:
    severity_for_score(score)
    if not CVSS_VECTOR_PATTERN.fullmatch(vector):
        raise ValueError(f"Invalid or unsupported CVSS v3.1 base vector: {vector}")


__all__ = ["severity_for_score", "validate_cvss"]
