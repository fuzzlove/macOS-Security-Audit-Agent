from __future__ import annotations

from mac_audit_agent.persistence_intelligence.models import PersistenceItem


def trust_label(score: int) -> str:
    if score >= 85:
        return "Legitimate"
    if score >= 70:
        return "Likely Legitimate"
    if score >= 50:
        return "Unknown"
    if score >= 35:
        return "Review Needed"
    if score >= 20:
        return "Suspicious"
    return "High Risk"


def score_trust(item: PersistenceItem) -> PersistenceItem:
    score = 50
    positives: list[str] = []
    negatives: list[str] = []
    target = item.executable_path or item.program or item.path
    if item.signed_status == "apple":
        score += 30
        positives.append("Apple-signed")
    elif item.signed_status == "valid":
        score += 18
        positives.append("valid signature")
    elif item.signed_status in {"unsigned", "invalid"}:
        score -= 18 if item.signed_status == "unsigned" else 30
        negatives.append(f"signature {item.signed_status}")
    if item.notarization_status == "notarized":
        score += 10
        positives.append("notarized")
    if str(target).startswith(("/System/Library", "/usr/bin", "/bin", "/sbin", "/usr/sbin")):
        score += 18
        positives.append("protected system path")
    if item.baseline_status in {"known", "unchanged"}:
        score += 10
        positives.append("stable baseline history")
    if item.baseline_status in {"new", "changed", "hash_changed"}:
        score -= 15
        negatives.append(f"baseline status {item.baseline_status}")
    if item.world_writable or item.writable_by_user:
        score -= 18
        negatives.append("writable path or target")
    if any(marker in str(target) for marker in ["/tmp", "/var/tmp", "/private/tmp", "/Users/Shared"]):
        score -= 20
        negatives.append("temporary/shared path")
    item.trust_score = max(0, min(100, score))
    item.trust_label = trust_label(item.trust_score)
    item.false_positive_notes = item.false_positive_notes or "Trust score is advisory only and should not suppress review by itself."
    item.warnings = [*item.warnings, *negatives]
    if positives:
        item.evidence.append("Trust positives: " + ", ".join(positives))
    return item
