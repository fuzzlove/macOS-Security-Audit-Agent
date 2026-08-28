from __future__ import annotations

from dataclasses import dataclass

from .models import GuardProfile


@dataclass(frozen=True)
class ClickFixPolicy:
    profile: GuardProfile = GuardProfile.WARN
    show_medium_alerts: bool = True
    clipboard_quarantine: bool = False
    fail_closed: bool = False
    correlation_window_seconds: int = 120
    notification_enabled: bool = True
    endpoint_security_containment: bool = False

    @classmethod
    def for_profile(cls, profile: GuardProfile) -> "ClickFixPolicy":
        return cls(
            profile=profile,
            show_medium_alerts=profile in {GuardProfile.WARN, GuardProfile.PROTECT, GuardProfile.HIGH_ASSURANCE},
            clipboard_quarantine=profile is GuardProfile.HIGH_ASSURANCE,
            fail_closed=profile is GuardProfile.HIGH_ASSURANCE,
            notification_enabled=profile is not GuardProfile.DISABLED,
            endpoint_security_containment=False,
        )

    @property
    def protect(self) -> bool:
        return self.profile in {GuardProfile.PROTECT, GuardProfile.HIGH_ASSURANCE}
