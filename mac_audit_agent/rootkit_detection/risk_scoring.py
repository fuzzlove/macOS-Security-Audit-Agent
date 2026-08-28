from __future__ import annotations

from dataclasses import dataclass, field

from mac_audit_agent.rootkit_detection.models import ExtensionInventoryItem, PortVisibilityFinding, SystemIntegrityPosture


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class RiskScore:
    score: int
    severity: str
    confidence: str
    reasons: list[str] = field(default_factory=list)
    false_positive_notes: list[str] = field(default_factory=list)


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def score_indicators(*, posture: SystemIntegrityPosture, extensions: list[ExtensionInventoryItem], ports: list[PortVisibilityFinding]) -> RiskScore:
    score = 0
    reasons: list[str] = []
    false_positive_notes = [
        "Security products, VPN clients, developer tools, and management agents can legitimately create privileged extensions or listeners.",
        "Visibility mismatches can be caused by permissions, timing, or short-lived processes.",
    ]
    if posture.sip_status == "disabled":
        score += 35
        reasons.append("SIP disabled")
    if posture.authenticated_root_status == "disabled":
        score += 35
        reasons.append("authenticated root disabled")
    if posture.boot_args:
        score += 20
        reasons.append("boot arguments present")
    risky_extensions = [item for item in extensions if item.risk_flags or item.signed_status == "unsigned" or (item.loaded and not item.team_id)]
    if risky_extensions:
        score += min(35, 15 + len(risky_extensions) * 5)
        reasons.append(f"{len(risky_extensions)} extension inventory item(s) require review")
    hidden_ports = [item for item in ports if item.visibility_status == "hidden_candidate"]
    missing_owner = [item for item in ports if item.visibility_status == "missing_owner"]
    if hidden_ports:
        score += min(40, 20 + len(hidden_ports) * 10)
        reasons.append(f"{len(hidden_ports)} hidden-port candidate(s)")
    elif missing_owner:
        score += min(20, 10 + len(missing_owner) * 3)
        reasons.append(f"{len(missing_owner)} listener(s) without owner in one tool")
    if risky_extensions and (posture.sip_status == "disabled" or posture.authenticated_root_status == "disabled"):
        score += 25
        reasons.append("risky extension plus weakened system integrity posture")
    if hidden_ports and risky_extensions:
        score += 25
        reasons.append("hidden-port candidate plus extension risk indicators")
    severity = severity_from_score(min(score, 100))
    confidence = "high" if score >= 85 else "medium" if reasons else "low"
    return RiskScore(score=min(score, 100), severity=severity, confidence=confidence, reasons=reasons, false_positive_notes=false_positive_notes)
