from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


AlertNoiseImpact = Literal["low", "medium", "high"]
Reversibility = Literal["reversible", "partially_reversible", "not_automatically_reversible"]
ApplyStatus = Literal["pending", "applied", "skipped", "failed"]


@dataclass
class FamilySafetyConfigChange:
    change_id: str
    category: str
    setting_path: str
    current_value: Any
    proposed_value: Any
    reason: str
    expected_effect: str
    user_visible_impact: str
    privacy_impact: str
    alert_noise_impact: AlertNoiseImpact
    reversibility: Reversibility
    requires_admin: bool = False
    requires_restart: bool = False
    standards_alignment: list[str] = field(default_factory=list)
    risk_if_not_applied: str = ""
    apply_status: ApplyStatus = "pending"
    failure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["FamilySafetyConfigChange", "AlertNoiseImpact", "Reversibility", "ApplyStatus"]
