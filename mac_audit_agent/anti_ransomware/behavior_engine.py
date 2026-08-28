"""Explainable, multi-signal ransomware behavior evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class RiskState(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ELEVATED = "elevated"
    PROBABLE = "probable_ransomware_behavior"
    CONFIRMED_POLICY = "confirmed_by_policy_threshold"
    CONTAINED = "contained"
    OBSERVATION_ONLY = "observation_only_due_to_missing_permissions"
    DEGRADED = "degraded_due_to_missing_sensor"


@dataclass(frozen=True)
class BehaviorSignal:
    signal_id: str
    confidence: float
    weight: int
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    high_confidence: bool = False


@dataclass(frozen=True)
class BehaviorAssessment:
    risk_state: RiskState
    score: int
    confidence: float
    signals: tuple[BehaviorSignal, ...]
    explanation: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["risk_state"] = self.risk_state.value
        value["threat_state"] = {
            RiskState.NORMAL: "NORMAL",
            RiskState.SUSPICIOUS: "SUSPICIOUS",
            RiskState.ELEVATED: "ELEVATED",
            RiskState.PROBABLE: "PROBABLE",
            RiskState.CONFIRMED_POLICY: "CONFIRMED",
            RiskState.CONTAINED: "CONTAINED",
            RiskState.OBSERVATION_ONLY: "UNKNOWN",
            RiskState.DEGRADED: "UNKNOWN",
        }[self.risk_state]
        return value


class RansomwareBehaviorEngine:
    """Requires corroboration; one signal can never produce probable ransomware."""

    def evaluate(self, signals: Iterable[BehaviorSignal], *, sensor_available: bool = True,
                 permissions_available: bool = True, containment_applied: bool = False) -> BehaviorAssessment:
        observed = tuple(signals)
        score = min(100, sum(max(0, item.weight) for item in observed))
        confidence = round(sum(item.confidence for item in observed) / len(observed), 3) if observed else 0.0
        strong = sum(item.high_confidence or item.confidence >= 0.8 for item in observed)
        independent = len({item.signal_id.split(":", 1)[0] for item in observed})
        if not sensor_available:
            state, limits = RiskState.DEGRADED, ("Primary sensor unavailable; conclusions are limited.",)
        elif not permissions_available:
            state, limits = RiskState.OBSERVATION_ONLY, ("Required macOS permissions are unavailable.",)
        elif score >= 90 and strong >= 3 and independent >= 3:
            state, limits = RiskState.CONFIRMED_POLICY, ()
        elif score >= 70 and strong >= 2 and independent >= 2:
            state, limits = RiskState.PROBABLE, ()
        elif score >= 45 and independent >= 2:
            state, limits = RiskState.ELEVATED, ()
        elif score >= 20 or observed:
            state, limits = RiskState.SUSPICIOUS, ()
        else:
            state, limits = RiskState.NORMAL, ()
        if containment_applied and state in {RiskState.PROBABLE, RiskState.CONFIRMED_POLICY}:
            state = RiskState.CONTAINED
        return BehaviorAssessment(state, score, confidence, observed, tuple(item.explanation for item in observed), limits)


__all__ = ["BehaviorAssessment", "BehaviorSignal", "RansomwareBehaviorEngine", "RiskState"]
