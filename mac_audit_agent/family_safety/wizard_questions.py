from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal


AnswerType = Literal["single_choice", "multiple_choice", "yes_no", "scale", "text_optional"]


@dataclass(frozen=True)
class FamilySafetyQuestion:
    question_id: str
    prompt: str
    help_text: str
    answer_type: AnswerType
    options: list[str]
    default_option: str
    affects_settings: list[str]
    standards_context: list[str]
    privacy_note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def canonical_family_safety_questions() -> list[FamilySafetyQuestion]:
    return [
        FamilySafetyQuestion("primary_user", "Who primarily uses this Mac?", "This selects a use-context profile and visibility level. A selection does not prove employment, asset ownership, regulatory scope, authorization, or compliance.", "single_choice", ["Adult / owner", "Child", "Teen", "Elder / at-risk user", "Shared family device", "School/student device", "Security/admin workstation", "Security research device", "Government asset", "Doctor / clinician device", "Nurse workstation", "Health device", "Lawyer / legal asset"], "Adult / owner", ["profile"], ["NIST CSF Identify", "NIST SP 800-53 AC"], "Answers stay local and are device-use labels, not verified professional or government identities."),
        FamilySafetyQuestion("shared_device", "Is this device shared?", "Shared devices usually need stronger account, device, and network review.", "single_choice", ["Private device", "Shared by family", "Shared by school/work", "Unknown"], "Private device", ["event_categories.usb", "event_categories.bluetooth", "event_categories.admin"], ["NIST CSF Protect", "CISA CPG account security"], "Shared status is used only for local recommendation logic."),
        FamilySafetyQuestion("alert_style", "What alert style do you prefer?", "Controls alert volume and severity thresholds.", "single_choice", ["Minimal alerts", "Important alerts only", "Balanced alerts", "High visibility", "Strict / security-focused"], "Balanced alerts", ["alerting.notify_all_events", "alerting.notify_important_events", "alerting.notify_min_severity"], ["NIST CSF Detect", "NIST SP 800-53 AU"], ""),
        FamilySafetyQuestion("bottom_right_alerts", "Should MSAA show bottom-right alerts for important changes?", "Bottom-right alerts are local visible notifications for important safety events.", "single_choice", ["Yes", "No", "Ask per category"], "Yes", ["notification.bottom_right_alerts", "user_notifier.enabled"], ["NIST CSF Detect"], "No cloud notification service is used by the wizard."),
        FamilySafetyQuestion("device_monitoring", "Should MSAA monitor new USB and Bluetooth devices?", "Device monitoring helps detect unexpected peripherals and local physical access risks.", "single_choice", ["Yes, alert for all new devices", "Yes, alert only for unknown/high-risk devices", "Inventory only", "No"], "Yes, alert only for unknown/high-risk devices", ["event_categories.usb_monitoring_enabled", "event_categories.bluetooth_monitoring_enabled"], ["NIST SP 800-53 MP", "CMMC Media Protection"], ""),
        FamilySafetyQuestion("network_monitoring", "Should MSAA monitor network changes?", "Network monitoring covers DNS, gateway, VPN, new listeners, and suspicious connections.", "single_choice", ["Yes, alert for DNS/gateway/VPN/new listeners", "Yes, alert only for suspicious changes", "Inventory only", "No"], "Yes, alert only for suspicious changes", ["event_categories.network_activity_monitoring_enabled"], ["NIST SP 800-53 SC", "CISA CPG logging"], ""),
        FamilySafetyQuestion("admin_persistence_monitoring", "Should MSAA monitor persistence and admin changes?", "Persistence/admin monitoring detects new admin accounts, sudoers changes, LaunchAgents, LaunchDaemons, and login items.", "single_choice", ["Yes, high visibility", "Yes, important alerts only", "Inventory/report only", "No"], "Yes, important alerts only", ["event_categories.admin_persistence_monitoring_enabled"], ["NIST SP 800-53 CM", "CMMC Configuration Management"], ""),
        FamilySafetyQuestion("preserve_evidence", "Should MSAA preserve evidence for review?", "Evidence preservation keeps local context so changes can be reviewed later.", "single_choice", ["Yes", "No", "Ask before preserving"], "Yes", ["evidence.preserve_evidence"], ["NIST CSF Respond", "NIST SP 800-53 IR"], "Evidence remains local unless exported by the user."),
        FamilySafetyQuestion("privacy_visibility", "Is privacy more important than visibility for this setup?", "Privacy-first reduces low-value alerts and emphasizes reports/manual review.", "single_choice", ["Privacy-first", "Balanced", "Visibility-first"], "Balanced", ["alerting.notify_all_events", "alerting.notify_min_severity"], ["NIST CSF Govern"], "The wizard does not expand data collection beyond selected local event categories."),
        FamilySafetyQuestion("government_hardening", "Do you want government-inspired hardening recommendations?", "Adds mapped strict readiness guidance without claiming compliance or approval.", "single_choice", ["Yes, NIST/CISA/NSA-style strict recommendations", "Yes, balanced recommendations", "No, family-only recommendations"], "No, family-only recommendations", ["profile", "manual_review_items"], ["NIST CSF 2.0", "NIST SP 800-53 Rev. 5", "CISA CPG", "CMMC readiness", "NSA public guidance"], ""),
        FamilySafetyQuestion("auto_apply", "Should MSAA automatically apply the recommended settings?", "Preview mode never applies. Apply after confirmation still requires explicit confirmation on the preview page.", "single_choice", ["Preview only", "Apply after confirmation", "Save as draft profile"], "Preview only", ["wizard.apply_mode"], ["NIST CSF Govern"], "No settings are changed silently."),
    ]


__all__ = ["FamilySafetyQuestion", "canonical_family_safety_questions"]
