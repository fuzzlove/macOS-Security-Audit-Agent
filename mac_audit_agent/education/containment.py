from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum

from .accessibility import AccessibilityImpactReview, review_asset_impact
from .models import DistrictAsset


class ActionNamespace(StrEnum):
    CYBER_CONTAINMENT = "CYBER_CONTAINMENT"
    PHYSICAL_EMERGENCY_ACTION = "PHYSICAL_EMERGENCY_ACTION"


@dataclass(frozen=True)
class ContainmentPlan:
    action_id: str
    namespace: ActionNamespace
    action: str
    target: DistrictAsset
    expires_at: datetime
    rollback: str
    approvers: tuple[str, ...]
    dry_run: bool = True
    high_impact: bool = False

    def authorize(self, review: AccessibilityImpactReview, *, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        if self.namespace is ActionNamespace.PHYSICAL_EMERGENCY_ACTION:
            raise PermissionError("[EDU-SAFE001] MSAA cannot automate doors, alarms, dispatch, or physical emergency actions.")
        if self.expires_at.tzinfo is None or self.expires_at <= now:
            raise ValueError("[EDU-SAFE002] Cyber containment requires a future timezone-aware expiration.")
        if not self.rollback.strip():
            raise ValueError("[EDU-SAFE003] Cyber containment requires a tested rollback procedure.")
        required = 2 if self.high_impact else 1
        if len(set(self.approvers)) < required:
            raise PermissionError(f"[EDU-SAFE004] This action requires {required} distinct approver(s); detected={len(set(self.approvers))}.")
        review_asset_impact(self.target, review)
