"""Readiness evidence mappings; never represents certification or compliance."""

from dataclasses import asdict, dataclass
from typing import Any


VALID_CLASSIFICATIONS = {
    "cmmc_readiness_issue", "nist_control_gap", "cisa_ransomware_guidance_gap",
    "mitre_attack_behavior", "local_security_hardening_issue",
    "evolutionary_security_opportunity", "analyst_review_required",
}


@dataclass(frozen=True)
class StandardsFinding:
    classification: str
    framework: str
    references: tuple[str, ...]
    evidence_support: str
    manual_evidence_required: bool
    disclaimer: str = "Readiness evidence only; this is not certification or a compliance determination."

    def __post_init__(self) -> None:
        if self.classification not in VALID_CLASSIFICATIONS:
            raise ValueError("unsupported standards classification")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def map_readiness(*, audit_logging: bool, recovery_ready: bool, containment_policy: bool) -> list[StandardsFinding]:
    findings: list[StandardsFinding] = []
    if not audit_logging:
        findings.extend([
            StandardsFinding("cmmc_readiness_issue", "CMMC readiness support", ("Audit and Accountability",), "Local anti-ransomware audit evidence is incomplete.", True),
            StandardsFinding("nist_control_gap", "NIST SP 800-53 Rev. 5", ("AU", "SI"), "Technical logging evidence is unavailable.", True),
        ])
    if not recovery_ready:
        findings.extend([
            StandardsFinding("cisa_ransomware_guidance_gap", "CISA StopRansomware", ("recovery readiness", "backup hygiene"), "Recovery readiness was not demonstrated.", True),
            StandardsFinding("nist_control_gap", "NIST SP 800-53 Rev. 5", ("CP", "IR"), "Recovery evidence needs review.", True),
        ])
    if not containment_policy:
        findings.append(StandardsFinding("analyst_review_required", "Local policy", ("IR",), "Containment remains observe-only until locally authorized.", True))
    return findings


__all__ = ["StandardsFinding", "VALID_CLASSIFICATIONS", "map_readiness"]
