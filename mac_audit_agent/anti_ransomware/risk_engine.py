from __future__ import annotations

from uuid import uuid4

from .models import DetectionDecision, DetectionSignal


def decide(signals: list[DetectionSignal], *, critical_continuity: bool = False) -> DetectionDecision:
    score = max(0, min(100, sum(signal.weight for signal in signals)))
    confidence = "high" if score >= 80 else "medium" if score >= 50 else "low"
    automatic = score >= 85 and not critical_continuity
    response = "pause_exact_process" if automatic else "manual_review" if score >= 50 else "observe"
    return DetectionDecision(
        decision_id=f"ar-decision-{uuid4().hex}", score=score, confidence=confidence,
        severity="critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low",
        recommended_response=response, automatic_response_eligible=automatic,
        signals=tuple(signals),
    )
