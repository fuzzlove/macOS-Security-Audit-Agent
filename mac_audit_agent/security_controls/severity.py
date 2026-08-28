from __future__ import annotations

from dataclasses import dataclass

from .models import AuthorizationStatus, PolicyProfile


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    severity: str
    rationale: str
    contributing_factors: tuple[str, ...]
    confidence: float
    scoring_version: str = "security-controls-risk-v1"


BASE_IMPACT = {"self_protection": 8.8, "system_integrity": 8.5, "disk_encryption": 8.2, "remote_access": 7.0, "identity": 7.0, "privacy": 6.8, "network_security": 6.5, "persistence": 6.2, "updates": 5.8, "network_configuration": 5.3, "application_assessment": 5.8}


def severity_for(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 5 else "low" if score >= 3 else "informational"


def assess_risk(*, category: str, authorization_status: str, reduces_security: bool, process_trusted: bool | None, remote_session: bool | None, asset_criticality: float = 1.0, confidence: float = 0.8, profile: PolicyProfile = PolicyProfile.STANDARD, related_control_count: int = 1) -> RiskAssessment:
    factors: list[str] = []
    score = BASE_IMPACT.get(category, 5.0)
    if reduces_security: factors.append("Security protection was reduced")
    else: score -= 1.5; factors.append("Change did not clearly reduce protection")
    if authorization_status == AuthorizationStatus.AUTHORIZED.value: score -= 4.0; factors.append("Valid scoped authorization was present")
    else: score += 1.0; factors.append("No valid scoped authorization was established")
    if process_trusted is False: score += 1.0; factors.append("Process identity was untrusted or unsigned")
    if remote_session: score += 0.6; factors.append("Change was associated with a remote session")
    if related_control_count >= 3: score += 1.2; factors.append("Multiple security controls changed in a bounded correlation window")
    multiplier = max(0.8, min(1.2, asset_criticality))
    if profile == PolicyProfile.HIGH_ASSURANCE: multiplier = min(1.25, multiplier + 0.05)
    score = round(max(0.0, min(10.0, score * multiplier)), 1)
    severity = severity_for(score)
    return RiskAssessment(score, severity, f"{severity.title()} incident risk based on control impact, authorization, attribution, and asset policy.", tuple(factors), max(0.0, min(1.0, confidence)))
