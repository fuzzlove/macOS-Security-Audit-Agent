"""Supported macOS handoffs for Family & Safety device-role setup.

MSAA settings are applied by ``apply_engine``. Apple-owned controls remain
subject to macOS user approval or device-management policy; this module never
edits protected preference databases or claims that opening Settings changed a
control.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable


SCREEN_TIME_SETTINGS_URL = "x-apple.systempreferences:com.apple.Screen-Time-Settings.extension"
USERS_GROUPS_SETTINGS_URL = "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"
DEVICE_MANAGEMENT_SETTINGS_URL = "x-apple.systempreferences:com.apple.Profiles-Settings.extension"


@dataclass(frozen=True)
class FamilySystemSetupAction:
    action_id: str
    title: str
    desired_state: str
    automation: str
    reason: str
    verification: str
    settings_url: str = ""
    management_payload: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_CHILD_PROFILES = {"child_minor_safety", "teen_shared_device_safety", "school_student_device"}
_MANAGED_PROFILES = {"school_student_device", "government_asset", "clinical_health_device"}


def build_family_system_setup_plan(profile_id: str) -> list[FamilySystemSetupAction]:
    """Return bounded, explainable OS actions for a selected device role."""

    actions: list[FamilySystemSetupAction] = []
    if profile_id in _CHILD_PROFILES:
        actions.append(
            FamilySystemSetupAction(
                "macos.screen_time",
                "Screen Time and Content & Privacy",
                "Turn on App & Website Activity and review age-appropriate downtime, app limits, communication, purchase, web, and privacy restrictions.",
                "USER_APPROVAL_REQUIRED",
                "macOS requires the device owner or Family Sharing parent/guardian to authorize Screen Time controls.",
                "Re-run the Family & Safety audit and confirm Screen Time evidence is present; review the selected limits in System Settings.",
                SCREEN_TIME_SETTINGS_URL,
                "com.apple.familycontrols.timelimits.v2 / com.apple.familycontrols.contentfilter",
            )
        )
        actions.append(
            FamilySystemSetupAction(
                "macos.standard_account",
                "Standard user account",
                "Use a standard account for the child, teen, or student unless an approved workflow requires administrator rights.",
                "USER_APPROVAL_REQUIRED",
                "Changing account privileges can interrupt administration and requires an administrator decision.",
                "Re-run the account audit and confirm the intended user is not an unexpected administrator.",
                USERS_GROUPS_SETTINGS_URL,
            )
        )
    if profile_id in _MANAGED_PROFILES:
        actions.append(
            FamilySystemSetupAction(
                "macos.managed_policy",
                "Managed restrictions and policy",
                "Apply the organization-approved parental controls, content filter, application restrictions, and account policy through MDM.",
                "MDM_REQUIRED",
                "MSAA cannot impersonate an MDM server or choose organization policy for a school, government, or clinical owner.",
                "Confirm the installed profile identifier, version, scope, and effective state with the device owner or MDM administrator.",
                DEVICE_MANAGEMENT_SETTINGS_URL,
                "Apple device-management restrictions and parental-control payloads",
            )
        )
    if not actions:
        actions.append(
            FamilySystemSetupAction(
                "macos.screen_time_optional_review",
                "Optional Screen Time review",
                "Review App & Website Activity, downtime, app limits, and Content & Privacy only if they match the owner-approved use of this Mac.",
                "OPTIONAL_USER_REVIEW",
                "Adult, research, legal, and specialist workstation roles should not receive arbitrary usage restrictions from a generic profile.",
                "Record the owner decision; do not treat an intentionally unused Screen Time control as malware or compromise.",
                SCREEN_TIME_SETTINGS_URL,
            )
        )
    return actions


def execute_family_system_setup_handoff(
    actions: list[FamilySystemSetupAction],
    *,
    opener: Callable[[str], bool],
    max_opened: int = 1,
) -> list[dict[str, Any]]:
    """Open at most one approved Apple settings destination and report truthfully."""

    allowed_urls = {SCREEN_TIME_SETTINGS_URL, USERS_GROUPS_SETTINGS_URL, DEVICE_MANAGEMENT_SETTINGS_URL}
    opened = 0
    results: list[dict[str, Any]] = []
    for action in actions:
        result = action.to_dict()
        result.update({"changed": False, "verified": False})
        if action.automation == "MDM_REQUIRED":
            result["status"] = "MDM_REQUIRED"
        elif action.settings_url and action.settings_url in allowed_urls and opened < max(0, int(max_opened)):
            try:
                was_opened = bool(opener(action.settings_url))
            except Exception as exc:
                result.update({"status": "HANDOFF_FAILED", "error": f"{type(exc).__name__}: {exc}"})
            else:
                result["status"] = "OPENED_FOR_USER_APPROVAL" if was_opened else "HANDOFF_FAILED"
                if was_opened:
                    opened += 1
        else:
            result["status"] = "QUEUED_FOR_USER_REVIEW"
        results.append(result)
    return results


__all__ = [
    "DEVICE_MANAGEMENT_SETTINGS_URL",
    "FamilySystemSetupAction",
    "SCREEN_TIME_SETTINGS_URL",
    "USERS_GROUPS_SETTINGS_URL",
    "build_family_system_setup_plan",
    "execute_family_system_setup_handoff",
]
