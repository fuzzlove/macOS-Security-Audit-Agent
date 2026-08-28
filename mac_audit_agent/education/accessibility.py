from __future__ import annotations

from dataclasses import dataclass

from .models import AccommodationDescriptor, DistrictAsset


@dataclass(frozen=True)
class AccessibilityImpactReview:
    reviewer: str
    affected_services: tuple[AccommodationDescriptor, ...] = ()
    emergency_communications_affected: bool = False
    accessible_alternative: str | None = None
    reversible: bool = False
    consulted_accessibility_role: bool = False
    immediate_life_safety_exception: bool = False

    @property
    def approved(self) -> bool:
        interference = bool(self.affected_services or self.emergency_communications_affected)
        ordinary_ok = not interference and self.reversible and self.consulted_accessibility_role
        exception_ok = (
            self.immediate_life_safety_exception
            and self.reversible
            and bool(self.accessible_alternative)
        )
        return ordinary_ok or exception_ok


def review_asset_impact(asset: DistrictAsset, review: AccessibilityImpactReview) -> None:
    blocked = set(asset.accommodations).intersection(review.affected_services)
    emergency_blocked = asset.emergency_service and review.emergency_communications_affected
    if blocked or emergency_blocked or not review.approved:
        raise PermissionError(
            "[EDU-A11Y001] Accessibility and Educational Access Impact Review failed; "
            f"asset={asset.asset_id}, blocked_services={sorted(x.value for x in blocked)}, "
            f"emergency_communications_affected={emergency_blocked}. "
            "Document an accessible alternative, consultation, reversibility, and authorized exception before deployment."
        )
