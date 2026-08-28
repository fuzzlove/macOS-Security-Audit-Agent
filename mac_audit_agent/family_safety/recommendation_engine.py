from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.family_safety.config_change import FamilySafetyConfigChange
from mac_audit_agent.family_safety.profiles import FamilySafetyProfile, profile_by_id


STANDARDS_ALIGNMENT = [
    "Mapped to NIST CSF 2.0: Identify, Protect, Detect, Respond, Recover",
    "Mapped to NIST SP 800-53 Rev. 5: AC, AU, CM, IR, SI, SC, MP",
    "Aligned with CISA CPG: account security, logging, incident response, security configuration",
    "Mapped to CMMC readiness domains: AC, AU, CM, IR, MP, SC, SI",
    "Aligned with NSA public hardening guidance in general terms only; no NSA approval is claimed.",
]


@dataclass
class FamilySafetyRecommendation:
    recommendation_id: str
    selected_profile: FamilySafetyProfile
    confidence: float
    reasoning: list[str]
    proposed_changes: list[FamilySafetyConfigChange]
    unchanged_settings: list[FamilySafetyConfigChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    privacy_notes: list[str] = field(default_factory=list)
    standards_alignment: list[str] = field(default_factory=list)
    manual_review_items: list[str] = field(default_factory=list)
    revert_plan: list[str] = field(default_factory=list)
    answers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["selected_profile"] = self.selected_profile.to_dict()
        payload["proposed_changes"] = [item.to_dict() for item in self.proposed_changes]
        payload["unchanged_settings"] = [item.to_dict() for item in self.unchanged_settings]
        return payload


def _get_path(settings: Any, setting_path: str) -> Any:
    current = settings
    for part in setting_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _profile_for_answers(answers: dict[str, Any]) -> tuple[str, list[str], float]:
    primary = str(answers.get("primary_user", "Adult / owner"))
    shared = str(answers.get("shared_device", "Private device"))
    gov = str(answers.get("government_hardening", "No, family-only recommendations"))
    reasons: list[str] = []
    confidence = 0.78
    contextual_profiles = {
        "Security research device": ("security_research_device", "Security research requires strong provenance, evidence, network-scope, and recovery review."),
        "Government asset": ("government_asset", "Government asset handling requires organization-approved baselines, authorization, and data-handling review."),
        "Doctor / clinician device": ("clinical_health_device", "Clinical use requires privacy, availability, approved application, and patient-data boundary review."),
        "Nurse workstation": ("clinical_health_device", "Nursing workflow requires privacy, shared-workstation, session, availability, and approved application review."),
        "Health device": ("clinical_health_device", "Health-device use requires safety, availability, privacy, vendor-support, and network-segmentation review."),
        "Lawyer / legal asset": ("legal_confidentiality_asset", "Legal work requires client-confidentiality, privilege, retention, access, and secure communication review."),
    }
    if primary in contextual_profiles:
        profile_id, reason = contextual_profiles[primary]
        return profile_id, [reason, "The selected label is self-declared use context and does not establish regulated status or compliance."], 0.86
    if "NIST/CISA/NSA-style strict" in gov or primary == "Security/admin workstation":
        return "high_security_government_lockdown", ["High-security or government-inspired hardening was selected."], 0.9
    if primary == "Child":
        return "child_minor_safety", ["A child/minor setup benefits from stronger device, network, admin, and persistence visibility."], 0.88
    if primary == "Teen" or shared == "Shared by family":
        return "teen_shared_device_safety", ["Teen/shared device answers favor balanced supervision with privacy-respecting alerts."], 0.84
    if primary == "Elder / at-risk user":
        return "elder_at_risk_safety", ["At-risk user setups benefit from unusual access, remote access, and new-device visibility."], 0.86
    if primary == "School/student device" or shared == "Shared by school/work":
        return "school_student_device", ["School/student answers favor evidence preservation and device/network awareness."], 0.84
    if str(answers.get("privacy_visibility")) == "Privacy-first":
        reasons.append("Privacy-first answer reduces noisy alerting and emphasizes manual review.")
        confidence = 0.74
    return "balanced_family_safety", reasons or ["General household answers match the balanced family profile."], confidence


def _answer_overrides(answers: dict[str, Any]) -> list[dict[str, Any]]:
    overrides: list[dict[str, Any]] = []

    alert_style = str(answers.get("alert_style", "Balanced alerts"))
    if alert_style == "Minimal alerts":
        overrides += [
            {"setting_path": "alerting.notify_all_events", "value": False, "category": "Alerts", "reason": "Minimal alerts were selected."},
            {"setting_path": "alerting.notify_min_severity", "value": "medium", "category": "Alerts", "reason": "Minimal alerts reduce lower-severity notifications."},
        ]
    elif alert_style == "Important alerts only":
        overrides += [
            {"setting_path": "alerting.notify_all_events", "value": False, "category": "Alerts", "reason": "Important-alerts-only mode was selected."},
            {"setting_path": "alerting.notify_min_severity", "value": "medium", "category": "Alerts", "reason": "Important-alerts-only mode suppresses low informational events."},
        ]
    elif alert_style in {"High visibility", "Strict / security-focused"}:
        overrides += [
            {"setting_path": "alerting.notify_all_events", "value": True, "category": "Alerts", "reason": f"{alert_style} was selected."},
            {"setting_path": "alerting.notify_min_severity", "value": "info", "category": "Alerts", "reason": f"{alert_style} favors broad local visibility."},
            {"setting_path": "notification.critical_overlay", "value": True, "category": "Alerts", "reason": f"{alert_style} should keep critical events visible."},
        ]

    bottom_right = str(answers.get("bottom_right_alerts", "Yes"))
    if bottom_right == "No":
        overrides.append({"setting_path": "notification.bottom_right_alerts", "value": False, "category": "Alerts", "reason": "Bottom-right alerts were declined."})

    device = str(answers.get("device_monitoring", "Yes, alert only for unknown/high-risk devices"))
    if device == "Inventory only":
        overrides += [
            {"setting_path": "event_categories.usb_new_device_alerts_enabled", "value": False, "category": "Devices", "reason": "Inventory-only device monitoring was selected."},
            {"setting_path": "event_categories.bluetooth_new_device_alerts_enabled", "value": False, "category": "Devices", "reason": "Inventory-only device monitoring was selected."},
        ]
    elif device == "No":
        overrides += [
            {"setting_path": "event_categories.usb_monitoring_enabled", "value": False, "category": "Devices", "reason": "USB/Bluetooth monitoring was declined."},
            {"setting_path": "event_categories.bluetooth_monitoring_enabled", "value": False, "category": "Devices", "reason": "USB/Bluetooth monitoring was declined."},
            {"setting_path": "event_categories.usb", "value": False, "category": "Devices", "reason": "USB/Bluetooth monitoring was declined."},
            {"setting_path": "event_categories.bluetooth", "value": False, "category": "Devices", "reason": "USB/Bluetooth monitoring was declined."},
        ]

    network = str(answers.get("network_monitoring", "Yes, alert only for suspicious changes"))
    if network == "Yes, alert only for suspicious changes":
        overrides += [
            {"setting_path": "event_categories.network_dns_gateway_alerts_enabled", "value": False, "category": "Network", "reason": "Suspicious-only network alerts reduce routine change noise."},
            {"setting_path": "event_categories.network_vpn_alerts_enabled", "value": False, "category": "Network", "reason": "Suspicious-only network alerts reduce routine change noise."},
        ]
    elif network == "Inventory only":
        overrides += [
            {"setting_path": "event_categories.network_new_connection_alerts_enabled", "value": False, "category": "Network", "reason": "Inventory-only network monitoring was selected."},
            {"setting_path": "event_categories.network_new_listener_alerts_enabled", "value": False, "category": "Network", "reason": "Inventory-only network monitoring was selected."},
            {"setting_path": "event_categories.network_dns_gateway_alerts_enabled", "value": False, "category": "Network", "reason": "Inventory-only network monitoring was selected."},
            {"setting_path": "event_categories.network_vpn_alerts_enabled", "value": False, "category": "Network", "reason": "Inventory-only network monitoring was selected."},
        ]
    elif network == "No":
        overrides += [
            {"setting_path": "event_categories.network_activity_monitoring_enabled", "value": False, "category": "Network", "reason": "Network monitoring was declined."},
            {"setting_path": "event_categories.network", "value": False, "category": "Network", "reason": "Network monitoring was declined."},
        ]

    admin = str(answers.get("admin_persistence_monitoring", "Yes, important alerts only"))
    if admin == "Inventory/report only":
        overrides += [
            {"setting_path": "event_categories.admin_user_monitoring_enabled", "value": False, "category": "Admin and Persistence", "reason": "Inventory/report-only admin monitoring was selected."},
            {"setting_path": "event_categories.persistence_monitoring_enabled", "value": False, "category": "Admin and Persistence", "reason": "Inventory/report-only persistence monitoring was selected."},
        ]
    elif admin == "No":
        overrides += [
            {"setting_path": "event_categories.admin_persistence_monitoring_enabled", "value": False, "category": "Admin and Persistence", "reason": "Admin/persistence monitoring was declined."},
            {"setting_path": "event_categories.admin", "value": False, "category": "Admin and Persistence", "reason": "Admin/persistence monitoring was declined."},
            {"setting_path": "event_categories.persistence", "value": False, "category": "Admin and Persistence", "reason": "Admin/persistence monitoring was declined."},
        ]

    if str(answers.get("preserve_evidence", "Yes")) == "No":
        overrides.append({"setting_path": "evidence.preserve_evidence", "value": False, "category": "Evidence", "reason": "Evidence preservation was declined."})
    if str(answers.get("privacy_visibility")) == "Privacy-first":
        overrides += [
            {"setting_path": "alerting.notify_all_events", "value": False, "category": "Privacy", "reason": "Privacy-first mode reduces noisy low-value alerts."},
            {"setting_path": "alerting.notify_min_severity", "value": "medium", "category": "Privacy", "reason": "Privacy-first mode emphasizes reports and manual review."},
        ]
    return overrides


class FamilySafetyRecommendationEngine:
    def recommend(
        self,
        answers: dict[str, Any],
        current_settings: Any,
        current_monitor_mode: str = "",
        current_user_account_type: str = "",
        available_permissions: list[str] | None = None,
        existing_family_settings: dict[str, Any] | None = None,
        existing_alert_configuration: dict[str, Any] | None = None,
    ) -> FamilySafetyRecommendation:
        profile_id, reasons, confidence = _profile_for_answers(answers)
        profile = profile_by_id(profile_id)
        raw_changes = {item["setting_path"]: dict(item) for item in profile.configuration_changes}
        for item in _answer_overrides(answers):
            raw_changes[item["setting_path"]] = item

        proposed: list[FamilySafetyConfigChange] = []
        unchanged: list[FamilySafetyConfigChange] = []
        for setting_path, raw in sorted(raw_changes.items()):
            current = _get_path(current_settings, setting_path)
            proposed_value = raw["value"]
            noise = "high" if setting_path in {"alerting.notify_all_events"} and proposed_value else ("medium" if raw.get("category") in {"Devices", "Network", "Admin and Persistence"} else "low")
            change = FamilySafetyConfigChange(
                change_id=f"family_safety.{setting_path}",
                category=str(raw.get("category", "Family Safety")),
                setting_path=setting_path,
                current_value=current,
                proposed_value=proposed_value,
                reason=str(raw.get("reason", "Recommended by the selected Family & Safety profile.")),
                expected_effect=_expected_effect(setting_path, proposed_value),
                user_visible_impact=_visible_impact(setting_path, proposed_value),
                privacy_impact="Events remain local unless exported by the user.",
                alert_noise_impact=noise,  # type: ignore[arg-type]
                reversibility="reversible",
                requires_admin=False,
                requires_restart=setting_path.startswith(("event_categories.", "notification.", "alerting.")),
                standards_alignment=_standards_for_category(str(raw.get("category", ""))),
                risk_if_not_applied=_risk_for_category(str(raw.get("category", ""))),
            )
            if current == proposed_value:
                unchanged.append(change)
            else:
                proposed.append(change)

        warnings = [
            "No setting applies until the user confirms selected changes.",
            "After confirmation the wizard applies supported MSAA settings, then opens the first relevant Apple settings pane for controls that require owner, guardian, or administrator approval.",
            "MSAA never edits protected Screen Time databases or reports an Apple-controlled setting as changed until a later audit verifies it; organization-managed restrictions still require MDM policy.",
        ]
        if profile.profile_id == "high_security_government_lockdown":
            warnings.append("Government-inspired mappings are readiness guidance only and do not claim compliance, certification, authorization, or NSA approval.")
        return FamilySafetyRecommendation(
            recommendation_id=f"family-safety-rec-{uuid4().hex[:12]}",
            selected_profile=profile,
            confidence=confidence,
            reasoning=reasons + [f"Current monitor mode: {current_monitor_mode or 'unknown'}.", f"Current user account type: {current_user_account_type or 'unknown'}."],
            proposed_changes=proposed,
            unchanged_settings=unchanged,
            warnings=warnings,
            privacy_notes=profile.privacy_notes + ["No telemetry, no cloud upload, and no hidden monitoring expansion are used by this wizard."],
            standards_alignment=STANDARDS_ALIGNMENT if "government" in str(answers.get("government_hardening", "")).lower() or profile.profile_id == "high_security_government_lockdown" else STANDARDS_ALIGNMENT[:3],
            manual_review_items=profile.manual_review_items + ["Review these settings manually after using the wizard."],
            revert_plan=["A pre-change snapshot is created before apply.", "Restore changes only writes wizard-changed MSAA setting paths back to their prior values.", "Apple settings approved separately by the owner/guardian and organization-managed MDM policies must be reversed through their owning Apple or MDM workflow."],
            answers=dict(answers),
        )


def _expected_effect(setting_path: str, value: Any) -> str:
    if setting_path == "notification.bottom_right_alerts":
        return "MSAA will show local bottom-right alerts for important safety events." if value else "MSAA will not show bottom-right wizard-driven alerts."
    if setting_path.startswith("event_categories.usb") or setting_path.startswith("event_categories.bluetooth"):
        return "MSAA will monitor selected USB/Bluetooth device events locally." if value else "MSAA will reduce or disable selected USB/Bluetooth event alerts."
    if setting_path.startswith("event_categories.network"):
        return "MSAA will monitor selected network changes locally." if value else "MSAA will reduce or disable selected network change alerts."
    if setting_path.startswith("event_categories.admin") or setting_path.startswith("event_categories.persistence"):
        return "MSAA will monitor selected admin and persistence changes locally." if value else "MSAA will reduce or disable selected admin/persistence alerts."
    if setting_path == "evidence.preserve_evidence":
        return "MSAA will preserve local event evidence for review." if value else "MSAA will avoid preserving extra wizard-requested evidence."
    return "MSAA will update this local setting to match the selected profile."


def _visible_impact(setting_path: str, value: Any) -> str:
    if setting_path.startswith(("notification.", "alerting.")):
        return "You may see a different number of local alerts."
    if setting_path.startswith("event_categories."):
        return "You may see alerts when matching device, network, admin, or persistence changes are detected." if value else "Fewer alerts may appear for this category."
    if setting_path == "evidence.preserve_evidence":
        return "Local reports may include more event context for review." if value else "Reports may contain less preserved context."
    return "This changes local MSAA behavior only."


def _standards_for_category(category: str) -> list[str]:
    mapping = {
        "Devices": ["Mapped to NIST SP 800-53 MP and SI; CMMC Media Protection."],
        "Network": ["Mapped to NIST SP 800-53 SC and SI; CISA CPG logging."],
        "Admin and Persistence": ["Mapped to NIST SP 800-53 AC, AU, CM; CMMC Access Control and Configuration Management."],
        "Evidence": ["Mapped to NIST CSF Respond/Recover and NIST SP 800-53 IR/AU."],
        "Alerts": ["Mapped to NIST CSF Detect and NIST SP 800-53 AU/SI."],
    }
    return mapping.get(category, ["Mapped to NIST CSF Protect/Detect for review support only."])


def _risk_for_category(category: str) -> str:
    return {
        "Devices": "Unexpected physical devices may go unnoticed.",
        "Network": "Unexpected DNS, gateway, VPN, listener, or suspicious connection changes may be missed.",
        "Admin and Persistence": "New admin or persistence changes may be harder to notice.",
        "Evidence": "Later review may have less local context.",
        "Alerts": "Important local safety events may be less visible.",
    }.get(category, "The selected profile may be less effective.")


__all__ = ["FamilySafetyRecommendation", "FamilySafetyRecommendationEngine", "STANDARDS_ALIGNMENT"]
