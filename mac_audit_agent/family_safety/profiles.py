from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class FamilySafetyProfile:
    profile_id: str
    display_name: str
    description: str
    intended_use: str
    recommended_for: list[str]
    not_recommended_for: list[str]
    expected_behavior: list[str]
    privacy_notes: list[str]
    alerting_level: str
    monitoring_level: str
    configuration_changes: list[dict[str, Any]]
    manual_review_items: list[str]
    revert_supported: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _change(setting_path: str, value: Any, category: str, reason: str) -> dict[str, Any]:
    return {"setting_path": setting_path, "value": value, "category": category, "reason": reason}


def _base_changes(alert_level: str = "balanced") -> list[dict[str, Any]]:
    min_severity = {"minimal": "medium", "important": "medium", "balanced": "low", "high": "info", "strict": "info"}.get(alert_level, "low")
    return [
        _change("notification.bottom_right_alerts", True, "Alerts", "Show local alerts for important Family & Safety events."),
        _change("notification.critical_overlay", alert_level in {"high", "strict"}, "Alerts", "Keep critical warnings visible for high-risk changes."),
        _change("alerting.notify_important_events", True, "Alerts", "Notify on important local safety events."),
        _change("alerting.notify_all_events", alert_level in {"high", "strict"}, "Alerts", "Increase visibility for setups that prefer supervision or strict monitoring."),
        _change("alerting.notify_min_severity", min_severity, "Alerts", "Tune alert volume to the selected visibility level."),
        _change("event_categories.usb", True, "Devices", "Keep USB visibility enabled."),
        _change("event_categories.bluetooth", True, "Devices", "Keep Bluetooth visibility enabled."),
        _change("event_categories.usb_monitoring_enabled", True, "Devices", "Monitor USB inventory changes locally."),
        _change("event_categories.bluetooth_monitoring_enabled", True, "Devices", "Monitor Bluetooth inventory changes locally."),
        _change("event_categories.usb_new_device_alerts_enabled", True, "Devices", "Alert when new USB devices appear."),
        _change("event_categories.bluetooth_new_device_alerts_enabled", True, "Devices", "Alert when new Bluetooth devices appear."),
        _change("event_categories.network", True, "Network", "Keep network change visibility enabled."),
        _change("event_categories.network_activity_monitoring_enabled", True, "Network", "Monitor network posture changes locally."),
        _change("event_categories.network_dns_gateway_alerts_enabled", True, "Network", "Alert on DNS and gateway changes."),
        _change("event_categories.network_vpn_alerts_enabled", True, "Network", "Alert on VPN changes."),
        _change("event_categories.network_new_listener_alerts_enabled", True, "Network", "Alert on new local listeners and sharing exposure."),
        _change("event_categories.admin", True, "Admin and Persistence", "Keep admin-change visibility enabled."),
        _change("event_categories.persistence", True, "Admin and Persistence", "Keep persistence visibility enabled."),
        _change("event_categories.admin_persistence_monitoring_enabled", True, "Admin and Persistence", "Monitor admin and persistence changes."),
        _change("event_categories.admin_user_monitoring_enabled", True, "Admin and Persistence", "Alert on administrator account changes."),
        _change("event_categories.persistence_monitoring_enabled", True, "Admin and Persistence", "Alert on persistence changes."),
        _change("evidence.preserve_evidence", True, "Evidence", "Preserve local evidence for later review."),
    ]


def canonical_family_safety_profiles() -> list[FamilySafetyProfile]:
    common_privacy = [
        "MSAA applies local settings only and does not upload answers or reports.",
        "The wizard does not inspect messages, browsing history, screenshots, camera feeds, microphone audio, or keystrokes.",
    ]
    return [
        FamilySafetyProfile(
            "balanced_family_safety",
            "Balanced Family Safety",
            "General household protection with moderate alerts.",
            "General household protection with clear but not noisy local alerts.",
            ["adult owners", "shared family Macs", "general household use"],
            ["strict government workstations", "users needing minimal alerts"],
            ["Important safety events produce local alerts.", "Reports preserve context for manual review."],
            common_privacy,
            "balanced",
            "balanced",
            _base_changes("balanced"),
            ["Review Screen Time, app restrictions, sharing services, FileVault, and firewall manually."],
            True,
        ),
        FamilySafetyProfile(
            "child_minor_safety",
            "Child / Minor Safety",
            "Higher visibility and safer defaults for a child's account or device.",
            "Child account or device where caregivers need stronger visibility.",
            ["child devices", "caregiver-managed Macs"],
            ["privacy-first adult setups", "workstations requiring minimal prompts"],
            ["New devices, network changes, admin changes, and persistence changes are visible.", "Evidence is preserved locally for caregiver review."],
            common_privacy + ["Use Screen Time and Family Sharing controls manually with the child or guardian present."],
            "high",
            "high",
            _base_changes("high"),
            ["Manually review Screen Time, communication limits, content restrictions, app installs, and location sharing."],
            True,
        ),
        FamilySafetyProfile(
            "teen_shared_device_safety",
            "Teen / Shared Device Safety",
            "Balanced supervision, device awareness, and privacy-respecting alerts.",
            "Teen or shared family Mac where supervision and privacy both matter.",
            ["teen users", "shared family devices"],
            ["strict lockdown workstations", "young child devices needing maximum supervision"],
            ["Important changes are alerted without turning on noisy all-event alerts.", "Manual review remains part of the workflow."],
            common_privacy + ["Keeps lower-value alerts reduced to avoid excessive supervision."],
            "balanced",
            "balanced",
            _base_changes("balanced"),
            ["Review account separation, Screen Time boundaries, app installs, and sharing services manually."],
            True,
        ),
        FamilySafetyProfile(
            "elder_at_risk_safety",
            "Elder / At-Risk User Safety",
            "Detect unusual access, new devices, session changes, and remote access risks.",
            "Macs used by people who may be targeted by scams or remote-access abuse.",
            ["elders", "at-risk users", "caregiver-supported devices"],
            ["strict privacy-first setups without caregiver consent"],
            ["Remote access, network, new device, admin, and persistence changes get stronger visibility.", "Reports support trusted-helper review."],
            common_privacy + ["Caregiver review should be consensual and limited to security-relevant events."],
            "high",
            "high",
            _base_changes("high") + [_change("event_categories.session", True, "Session", "Keep session lock/unlock visibility for unusual access review.")],
            ["Manually review remote sharing, browser extensions, notification permissions, and trusted contacts."],
            True,
        ),
        FamilySafetyProfile(
            "school_student_device",
            "School / Student Device",
            "Basic monitoring, evidence preservation, device and network awareness.",
            "Student or school-managed Mac where local evidence and reviewability matter.",
            ["school devices", "student devices", "libraries"],
            ["personal privacy-first adult devices"],
            ["Device and network changes are visible.", "Evidence is preserved locally for authorized review."],
            common_privacy + ["School policy and consent requirements remain manual process controls."],
            "balanced",
            "balanced",
            _base_changes("balanced"),
            ["Review MDM profiles, Screen Time, content filtering, acceptable-use policy, and school consent requirements manually."],
            True,
        ),
        FamilySafetyProfile(
            "high_security_government_lockdown",
            "High-Security / Government-Inspired Lockdown",
            "Strict local-first monitoring aligned with NIST/CISA/NSA-style hardening guidance.",
            "Strict local-first monitoring for security/admin workstations.",
            ["security/admin workstations", "government-inspired readiness reviews", "high-risk users"],
            ["default family setups", "users who prefer minimal alerts"],
            ["Critical and high visibility overlays are enabled.", "USB/Bluetooth, network, admin, persistence, and evidence settings are strict."],
            common_privacy + ["Mapped to public guidance only; this does not claim compliance, certification, authorization, or NSA approval."],
            "strict",
            "strict",
            _base_changes("strict")
            + [
                _change("event_categories.network_new_connection_alerts_enabled", True, "Network", "Increase strict network visibility."),
                _change("event_categories.network_suspicious_connection_alerts_enabled", True, "Network", "Alert on suspicious connections."),
                _change("event_categories.launchagent_monitoring_enabled", True, "Admin and Persistence", "Monitor LaunchAgents."),
                _change("event_categories.launchdaemon_monitoring_enabled", True, "Admin and Persistence", "Monitor LaunchDaemons."),
                _change("event_categories.login_item_monitoring_enabled", True, "Admin and Persistence", "Monitor login items."),
            ],
            ["Manually review FileVault, firewall, sharing services, MDM/profile posture, backups, and incident response procedures."],
            True,
        ),
        FamilySafetyProfile(
            "security_research_device", "Security Research Device",
            "High-visibility local monitoring and evidence preservation for authorized macOS security research.",
            "Research devices holding unpublished findings, tools, or intellectual property.",
            ["authorized security research", "controlled research laboratories"], ["a claim of Apple SRD status", "unauthorized testing"],
            ["Device, network, administrator, persistence, and evidence events receive high visibility.", "Research authorization and disclosure remain manual controls."],
            common_privacy + ["Do not store exploit payloads, credentials, recovery keys, or unpublished vulnerability details in wizard answers or event notes."],
            "strict", "strict", _base_changes("strict") + [_change("event_categories.network_suspicious_connection_alerts_enabled", True, "Network", "Preserve suspicious research-device network changes."), _change("event_categories.launchdaemon_monitoring_enabled", True, "Admin and Persistence", "Monitor privileged persistence changes on the research device.")],
            ["Complete the Security Research Device wizard.", "Verify FileVault, Secure Boot, SIP, firewall, software provenance, approved network/DNS/VPN scope, encrypted recovery, research authorization, data classification, and coordinated-disclosure contacts."], True,
        ),
        FamilySafetyProfile(
            "government_asset", "Government Asset Readiness",
            "Strict evidence-oriented monitoring for a device asserted to be government-managed.",
            "Assets subject to a system owner's approved baseline and handling requirements.",
            ["authorized government-managed endpoints", "contractually scoped government work"], ["self-certification", "selecting a profile to obtain authorization"],
            ["High-visibility local monitoring and evidence preservation are enabled.", "Applicable baseline and authorization must be validated externally."],
            common_privacy + ["Do not enter classified, CUI, credentials, authorization documents, or mission details in wizard answers."],
            "strict", "strict", _base_changes("strict") + [_change("event_categories.network_suspicious_connection_alerts_enabled", True, "Network", "Increase visibility for scoped government assets."), _change("event_categories.launchagent_monitoring_enabled", True, "Admin and Persistence", "Monitor user persistence."), _change("event_categories.launchdaemon_monitoring_enabled", True, "Admin and Persistence", "Monitor privileged persistence.")],
            ["Confirm asset owner, authorization boundary, data classification, approved macOS STIG or organizational baseline, MDM posture, identity policy, audit retention, incident contacts, removable-media policy, backup, and recovery.", "Have the system security officer and authorizing official review unresolved controls."], True,
        ),
        FamilySafetyProfile(
            "clinical_health_device", "Clinical / Health Device Safety",
            "Availability- and privacy-conscious monitoring for clinician workstations and health-device contexts.",
            "Authorized clinical workflows where privacy, safe availability, and vendor-supported configuration matter.",
            ["doctor or nurse workstations", "health-device administration endpoints"], ["medical-device certification", "diagnosis or patient-safety decisions"],
            ["Unexpected devices, network changes, sessions, administrators, and persistence remain visible.", "Operational changes require clinical-owner and vendor review."],
            common_privacy + ["MSAA does not inspect or request patient records. Do not place PHI in notes, exports, or evidence unless an approved workflow explicitly permits it."],
            "high", "high", _base_changes("high") + [_change("event_categories.session", True, "Session", "Review access changes on clinical or shared workstations.")],
            ["Confirm whether the endpoint is in HIPAA or other regulated scope with privacy/security personnel.", "Review shared-session behavior, automatic lock, approved clinical apps, removable media, encryption, backups, downtime procedures, network segmentation, vendor support, patch validation, and emergency access without disrupting patient care."], True,
        ),
        FamilySafetyProfile(
            "legal_confidentiality_asset", "Legal Confidentiality Asset",
            "Privacy-focused protection for client-confidential and potentially privileged legal work.",
            "Authorized legal workstations requiring strong access, provenance, evidence, and retention review.",
            ["lawyer workstations", "legal support assets"], ["a determination of attorney-client privilege", "legal or records-management advice"],
            ["Unexpected device, network, administrator, and persistence changes remain visible.", "Client/matter scope and retention remain controlled by the organization."],
            common_privacy + ["Do not put client names, matter details, privileged content, discovery material, credentials, or legal strategy in wizard answers or event notes."],
            "high", "high", _base_changes("high"),
            ["Confirm FileVault and recovery custody, separate identities, screen lock, approved document and communication systems, data-loss controls, client/matter access, retention/legal hold, secure deletion, backup recovery, remote access, incident notification, and cross-border restrictions with qualified personnel."], True,
        ),
        FamilySafetyProfile(
            "custom_profile",
            "Custom Profile",
            "User-defined mix of controls.",
            "User-defined mix of wizard-selected controls.",
            ["users who want reviewable manual choices"],
            [],
            ["MSAA proposes only settings matching the wizard answers.", "Each selected change remains reviewable before apply."],
            common_privacy,
            "custom",
            "custom",
            [],
            ["Review every selected control manually before applying custom settings."],
            True,
        ),
    ]


def profile_by_id(profile_id: str) -> FamilySafetyProfile:
    profiles = {profile.profile_id: profile for profile in canonical_family_safety_profiles()}
    return profiles.get(profile_id, profiles["balanced_family_safety"])


__all__ = ["FamilySafetyProfile", "canonical_family_safety_profiles", "profile_by_id"]
