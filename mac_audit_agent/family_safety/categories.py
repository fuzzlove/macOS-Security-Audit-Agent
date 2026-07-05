from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


STATUS_CONFIGURED = "configured"
STATUS_NEEDS_REVIEW = "needs_review"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_UNAVAILABLE = "unavailable"
STATUS_MANUAL = "manual_verification_required"


@dataclass
class FamilyCategoryViewState:
    category_id: str
    selected_device_id: str = ""
    selected_checklist_item: str = ""
    filters: dict[str, Any] = field(default_factory=dict)
    expanded_sections: dict[str, bool] = field(default_factory=lambda: {
        "description": True,
        "checklist": True,
        "changes": True,
    })
    pending_changes: list[str] = field(default_factory=list)
    last_opened: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FamilySafetyCategory:
    category_id: str
    title: str
    short_description: str
    detailed_description: str
    who_it_helps: str
    why_it_matters: str
    what_is_checked: list[str]
    what_the_user_can_change: list[str]
    macos_settings_paths: list[str]
    risk_if_unconfigured: str
    recommended_for: list[str]
    nist_mappings: list[str]
    related_categories: list[str]
    checklist_items: list[str]
    current_status: str = STATUS_MANUAL
    pending_changes: list[str] = field(default_factory=list)
    last_reviewed_at: str = ""
    reset_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _cat(
    category_id: str,
    title: str,
    short_description: str,
    detailed_description: str,
    who_it_helps: str,
    why_it_matters: str,
    what_is_checked: list[str],
    what_the_user_can_change: list[str],
    macos_settings_paths: list[str],
    risk_if_unconfigured: str,
    recommended_for: list[str],
    nist_mappings: list[str],
    related_categories: list[str],
    checklist_items: list[str],
) -> FamilySafetyCategory:
    return FamilySafetyCategory(
        category_id=category_id,
        title=title,
        short_description=short_description,
        detailed_description=detailed_description,
        who_it_helps=who_it_helps,
        why_it_matters=why_it_matters,
        what_is_checked=what_is_checked,
        what_the_user_can_change=what_the_user_can_change,
        macos_settings_paths=macos_settings_paths,
        risk_if_unconfigured=risk_if_unconfigured,
        recommended_for=recommended_for,
        nist_mappings=nist_mappings,
        related_categories=related_categories,
        checklist_items=checklist_items,
    )


def canonical_family_safety_categories() -> list[FamilySafetyCategory]:
    nist_core = ["NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover"]
    return [
        _cat(
            "account_safety",
            "Account Safety",
            "Reviews accounts, administrator permissions, guest access, password settings, and account separation.",
            "Account Safety helps confirm each person has an appropriate local account and that administrator access is limited to trusted users.",
            "Parents, caregivers, schools, libraries, shared Macs, and security administrators.",
            "Shared admin credentials and automatic login make accidental changes, unwanted installs, and unauthorized access more likely.",
            ["admin users", "standard users", "guest account", "password requirement", "automatic login", "account sharing risks"],
            ["Move daily use to standard accounts", "Disable Guest access when not needed", "Disable automatic login", "Review administrator membership"],
            ["System Settings > Users & Groups", "System Settings > Lock Screen"],
            "Unconfigured accounts can allow unintended admin access or make it hard to attribute changes to the right person.",
            ["parents", "caregivers", "schools", "libraries", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: AC-2 Account Management", "NIST SP 800-53 Rev. 5: AC-6 Least Privilege"],
            ["screen_time_usage_controls", "government_nist_lockdown"],
            ["Review admin users", "Confirm standard user separation", "Disable Guest access unless needed", "Disable automatic login", "Require password after sleep or screensaver"],
        ),
        _cat(
            "screen_time_usage_controls",
            "Screen Time and Usage Controls",
            "Helps configure Screen Time for app limits, downtime, communication safety, and content restrictions.",
            "Screen Time and Usage Controls centralizes age-appropriate limits without inspecting private activity or message contents.",
            "Families, caregivers, special-needs caretakers, and shared-device managers.",
            "Clear limits and content controls reduce accidental exposure and make expectations easier to discuss.",
            ["Screen Time enabled", "app limits", "downtime", "communication limits", "content/privacy restrictions"],
            ["Enable Screen Time", "Set downtime", "Configure app limits", "Configure communication and content restrictions"],
            ["System Settings > Screen Time"],
            "Without Screen Time review, limits may be missing, inconsistent, or unclear to caregivers and users.",
            ["parents", "caregivers", "schools", "special-needs caretakers"],
            nist_core + ["NIST SP 800-53 Rev. 5: CM-6 Configuration Settings"],
            ["communication_messaging_safety", "web_browser_safety"],
            ["Confirm Screen Time is enabled", "Review app limits", "Review downtime", "Review communication limits", "Review Content & Privacy restrictions"],
        ),
        _cat(
            "web_browser_safety",
            "Web and Browser Safety",
            "Helps reduce exposure to malicious websites, adult content, unsafe downloads, popups, phishing, and tracking.",
            "Web and Browser Safety reviews protective settings and guidance without reading browsing history, cookies, tabs, or private browsing data.",
            "Families, schools, libraries, seniors, and high-risk users.",
            "Unsafe sites and deceptive downloads are common paths for scams, malware, and age-inappropriate content.",
            ["Safari safe browsing protections", "website restrictions", "popup blocking", "content blockers", "unsafe download guidance"],
            ["Enable fraudulent website warnings", "Review web content restrictions", "Block popups", "Install trusted content blockers", "Use safe download habits"],
            ["Safari > Settings > Security", "Safari > Settings > Websites", "System Settings > Screen Time > Content & Privacy"],
            "Users may be more exposed to phishing, deceptive popups, unsafe downloads, and inappropriate content.",
            ["parents", "caregivers", "schools", "libraries", "seniors"],
            nist_core + ["NIST SP 800-53 Rev. 5: SC-7 Boundary Protection"],
            ["downloads_file_safety", "communication_messaging_safety"],
            ["Turn on Safari Fraudulent Website Warning", "Review website restrictions", "Block popups", "Review content blockers", "Do not inspect browser history"],
        ),
        _cat(
            "app_store_application_controls",
            "App Store and Application Controls",
            "Reviews app installation sources, unknown developers, recently installed apps, and app permissions.",
            "Application controls help users decide which software belongs on the Mac using metadata and settings, not private documents.",
            "Families, shared-device managers, schools, libraries, and regulated workstations.",
            "Unexpected applications can introduce malware, privacy risks, subscriptions, or confusing prompts.",
            ["App Store restrictions", "unknown developer apps", "unsigned apps", "recently installed apps", "sensitive permissions"],
            ["Limit app installs", "Review unknown apps", "Remove apps that do not belong", "Prefer trusted developers"],
            ["System Settings > Screen Time > Content & Privacy", "System Settings > Privacy & Security"],
            "Unreviewed apps can request sensitive permissions or add unwanted background behavior.",
            ["parents", "schools", "libraries", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: CM-6 Configuration Settings"],
            ["privacy_permissions", "downloads_file_safety", "government_nist_lockdown"],
            ["Review App Store restrictions", "Review unsigned apps", "Review recently installed apps", "Review sensitive permissions"],
        ),
        _cat(
            "privacy_permissions",
            "Privacy Permissions",
            "Helps review apps with access to camera, microphone, location, contacts, photos, Bluetooth, local network, and screen recording.",
            "Privacy Permissions guides users to Apple's TCC-controlled settings and never bypasses those protections.",
            "Families, caregivers, seniors, schools, libraries, and security administrators.",
            "Overbroad permissions can expose sensitive data or create confusing trust decisions.",
            ["camera permission posture", "microphone permission posture", "location permission posture", "screen recording posture", "accessibility posture", "local network posture"],
            ["Remove unnecessary access", "Review sensitive app permissions", "Keep TCC prompts user-controlled"],
            ["System Settings > Privacy & Security"],
            "Apps may retain access they no longer need, increasing privacy and safety risk.",
            ["parents", "caregivers", "schools", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: AC-6 Least Privilege"],
            ["app_store_application_controls", "communication_messaging_safety"],
            ["Review Camera", "Review Microphone", "Review Location Services", "Review Screen Recording", "Review Accessibility", "Review Local Network"],
        ),
        _cat(
            "communication_messaging_safety",
            "Communication and Messaging Safety",
            "Guidance for reducing exposure to unsafe links, attachments, unknown contacts, phishing, and social engineering.",
            "Communication and Messaging Safety provides behavior and settings guidance without inspecting private messages or contacts.",
            "Parents, caregivers, seniors, schools, and high-risk users.",
            "Scams often start with urgent messages, unknown links, attachments, or requests for secrets and money.",
            ["recommended safety checklist", "FaceTime/iMessage safety guidance", "attachment caution", "communication limits where Screen Time supports it"],
            ["Review Screen Time communication limits", "Use safer attachment habits", "Create trusted-contact rules"],
            ["System Settings > Screen Time > Communication Limits", "Messages > Settings", "FaceTime > Settings"],
            "Users may be less prepared for phishing, coercion, unknown contacts, or unsafe attachments.",
            ["parents", "caregivers", "seniors", "special-needs caretakers"],
            nist_core + ["NIST SP 800-61 Rev. 3: Detection and Analysis"],
            ["screen_time_usage_controls", "web_browser_safety"],
            ["Review communication limits", "Discuss unknown contact rules", "Avoid unknown attachments", "Verify urgent requests through another channel"],
        ),
        _cat(
            "downloads_file_safety",
            "Downloads and File Safety",
            "Helps reduce risk from unknown downloads, executable files, disk images, installers, and scripts.",
            "Downloads and File Safety reviews file-risk indicators and guidance without reading private documents or browsing history.",
            "Families, seniors, schools, libraries, and regulated environments.",
            "Downloads are a common route for malware, unwanted software, and confusing installers.",
            ["downloads folder risk indicators", "executable files in downloads", "recent unsigned apps", "quarantine indicators where available"],
            ["Remove unneeded installers", "Avoid unknown scripts", "Review disk images and packages", "Keep Gatekeeper enabled"],
            ["Finder > Downloads", "System Settings > Privacy & Security"],
            "Unknown executables and installers may remain available for accidental launch.",
            ["parents", "caregivers", "schools", "libraries", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: SI-2 Flaw Remediation"],
            ["web_browser_safety", "app_store_application_controls"],
            ["Review executable files in Downloads", "Review disk images", "Review installer packages", "Confirm quarantine guidance"],
        ),
        _cat(
            "remote_access_sharing",
            "Remote Access and Sharing",
            "Reviews features that allow other devices or users to access the Mac.",
            "Remote Access and Sharing helps decide whether each sharing service is intentional and limited.",
            "Families, schools, libraries, shared Macs, and security administrators.",
            "Remote services can expose files, shells, screens, or management controls if enabled unexpectedly.",
            ["Remote Login", "Screen Sharing", "File Sharing", "Remote Management", "AirDrop", "Bluetooth Sharing if available"],
            ["Disable unused sharing services", "Restrict AirDrop", "Review remote administration needs"],
            ["System Settings > General > Sharing", "System Settings > Bluetooth", "Finder > AirDrop"],
            "Unneeded sharing services can increase local network and physical proximity exposure.",
            ["parents", "schools", "libraries", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: SC-7 Boundary Protection"],
            ["government_nist_lockdown", "lockdown_mode_plus"],
            ["Review Remote Login", "Review Screen Sharing", "Review File Sharing", "Review Remote Management", "Restrict AirDrop", "Review Bluetooth Sharing"],
        ),
        _cat(
            "device_physical_access_safety",
            "Device and Physical Access Safety",
            "Reviews USB, Bluetooth, HID devices, external storage, and physical-use indicators.",
            "Device and Physical Access Safety keeps device selections scoped to this category so stale USB or Bluetooth details do not appear elsewhere.",
            "Caregivers, schools, libraries, high-risk users, and security administrators.",
            "Physical access and unknown peripherals can introduce data theft, input spoofing, or unwanted network adapters.",
            ["new USB devices", "trusted USB devices", "Bluetooth devices", "unknown HID devices", "lock screen behavior", "idle resume alerts"],
            ["Review trusted devices", "Remove unknown pairings", "Improve lock-screen behavior", "Enable relevant monitor alerts"],
            ["System Settings > Bluetooth", "System Settings > Lock Screen", "System Information > USB"],
            "Unknown devices may remain trusted or unnoticed across shared and high-risk environments.",
            ["schools", "libraries", "caregivers", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: SI-4 System Monitoring"],
            ["remote_access_sharing", "government_nist_lockdown", "lockdown_mode_plus"],
            ["Review new USB devices", "Review Bluetooth devices", "Review unknown HID devices", "Review lock screen behavior", "Review idle resume alerts"],
        ),
        _cat(
            "backup_recovery",
            "Backup and Recovery",
            "Helps ensure important data can be recovered after accidental deletion, malware, theft, or device failure.",
            "Backup and Recovery focuses on recoverability, evidence snapshots, and clear guidance before cleanup or repairs.",
            "Families, caregivers, schools, libraries, and security administrators.",
            "A safe configuration still needs recovery options for mistakes, device loss, or incidents.",
            ["Time Machine status if available", "backup guidance", "recovery key guidance", "evidence snapshot guidance"],
            ["Enable backups", "Store recovery information safely", "Create evidence snapshots before cleanup"],
            ["System Settings > General > Time Machine", "System Settings > Privacy & Security > FileVault"],
            "Data and incident evidence may be lost after failure, theft, or cleanup.",
            ["parents", "caregivers", "schools", "government/security administrators"],
            nist_core + ["NIST CSF 2.0: Recover", "NIST SP 800-61 Rev. 3: Post-Incident Activity"],
            ["government_nist_lockdown", "lockdown_mode_plus"],
            ["Review Time Machine", "Review recovery key handling", "Use evidence snapshots before cleanup", "Confirm backup restoration path"],
        ),
        _cat(
            "special_needs_accessibility_safety",
            "Special Needs and Accessibility Safety",
            "Helps configure accessibility and safety settings for users who may need simplified controls, larger text, reduced motion, or assistive input.",
            "Special Needs and Accessibility Safety helps caretakers review supportive settings with the user's needs and consent in mind.",
            "Special-needs caretakers, caregivers, families, schools, and libraries.",
            "The safest setup is one the user can understand, navigate, and recover from without unnecessary friction.",
            ["VoiceOver", "Zoom", "Large Text", "Reduce Motion", "Switch Control", "Voice Control", "Assistive Access guidance if applicable"],
            ["Enable helpful accessibility supports", "Reduce confusing motion", "Simplify input", "Document caretaker guidance"],
            ["System Settings > Accessibility"],
            "Users may face avoidable confusion, inaccessible prompts, or unsafe workarounds.",
            ["special-needs caretakers", "caregivers", "schools"],
            nist_core + ["NIST CSF 2.0: Govern"],
            ["screen_time_usage_controls", "communication_messaging_safety"],
            ["Review VoiceOver", "Review Zoom", "Review Large Text", "Review Reduce Motion", "Review Switch Control", "Review Voice Control", "Review Assistive Access guidance"],
        ),
        _cat(
            "school_shared_device_mode",
            "School / Shared Device Mode",
            "Helps schools, labs, libraries, and shared-device environments reduce risk and standardize safer settings.",
            "School / Shared Device Mode organizes settings for Macs used by many people without turning the device into a surveillance tool.",
            "Schools, labs, libraries, classrooms, and shared family computers.",
            "Shared devices need predictable account, install, sharing, inventory, and reset expectations.",
            ["guest access", "remote access", "app installation", "sharing", "device inventory", "standard user profile guidance"],
            ["Use standard accounts", "Review Guest access", "Standardize app installs", "Document device inventory"],
            ["System Settings > Users & Groups", "System Settings > General > Sharing", "System Settings > Screen Time"],
            "Shared Macs may accumulate risky settings, unknown apps, or stale device trust.",
            ["schools", "libraries", "shared family computers"],
            nist_core + ["NIST SP 800-53 Rev. 5: CM-6 Configuration Settings"],
            ["account_safety", "remote_access_sharing", "app_store_application_controls"],
            ["Review Guest access", "Review remote access", "Review app installation policy", "Review sharing", "Review device inventory", "Use standard-user guidance"],
        ),
        _cat(
            "government_nist_lockdown",
            "Government / NIST Lockdown Profile",
            "Provides NIST-aligned macOS hardening guidance for public sector, regulated, and high-security environments.",
            "Government / NIST Lockdown Profile supports review of government-style hardening without claiming compliance, certification, or official authorization.",
            "Government/security administrators, public sector teams, schools, libraries, and regulated workstations.",
            "High-security environments need a clear, repeatable hardening checklist mapped to recognized framework language.",
            ["identity and access", "device encryption", "firewall and sharing", "system integrity", "logging and monitoring", "network", "application control", "external devices", "incident response"],
            ["Review least privilege", "Enable FileVault", "Disable unused sharing", "Enable monitoring", "Preserve logs before cleanup"],
            ["System Settings > Users & Groups", "System Settings > Privacy & Security", "System Settings > General > Sharing", "System Settings > Network"],
            "Systems may miss basic hardening controls, audit readiness, and incident response preparation.",
            ["government/security administrators", "schools", "libraries", "regulated environments"],
            [
                "NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover",
                "NIST SP 800-53 Rev. 5: AC-2 Account Management",
                "NIST SP 800-53 Rev. 5: AC-6 Least Privilege",
                "NIST SP 800-53 Rev. 5: AU-6 Audit Record Review",
                "NIST SP 800-53 Rev. 5: CM-6 Configuration Settings",
                "NIST SP 800-53 Rev. 5: IA-5 Authenticator Management",
                "NIST SP 800-53 Rev. 5: SC-7 Boundary Protection",
                "NIST SP 800-53 Rev. 5: SI-2 Flaw Remediation",
                "NIST SP 800-53 Rev. 5: SI-4 System Monitoring",
                "NIST SP 800-61 Rev. 3: Detection and Analysis",
                "NIST SP 800-61 Rev. 3: Containment, Eradication, and Recovery",
                "NIST SP 800-61 Rev. 3: Post-Incident Activity",
            ],
            ["account_safety", "remote_access_sharing", "backup_recovery", "lockdown_mode_plus"],
            [
                "Separate admin and standard accounts",
                "Disable automatic login",
                "Require password after sleep or screensaver",
                "Enable FileVault and protect recovery material",
                "Enable firewall",
                "Disable Remote Login unless required",
                "Disable Screen Sharing unless required",
                "Disable File Sharing unless required",
                "Disable Remote Management unless required",
                "Restrict AirDrop",
                "Confirm SIP and Gatekeeper posture",
                "Enable software updates and rapid security responses",
                "Enable MSAA monitor and notifier",
                "Review VPN, proxy, DNS, and local network exposure",
                "Review unsigned apps, launch items, persistence, and browser extensions",
                "Review USB, Bluetooth, storage, and HID devices",
                "Use Incident Mode and evidence snapshots before cleanup",
            ],
        ),
        _cat(
            "lockdown_mode_plus",
            "Lockdown Mode Plus",
            "Reviews additional macOS hardening settings that may complement Apple Lockdown Mode.",
            "Lockdown Mode Plus is not Apple Lockdown Mode, does not replace it, and does not guarantee protection. It provides additional local hardening checks and guidance.",
            "High-risk users, journalists, activists, executives, caregivers for targeted users, and security administrators.",
            "Users who need stronger protection benefit from reducing remote access, sharing, unknown devices, unknown apps, and update delays.",
            ["Apple Lockdown Mode manual verification", "remote access", "AirDrop", "Bluetooth", "USB devices", "profiles", "VPN/proxy/DNS", "browser extensions", "unknown apps", "LaunchAgents/LaunchDaemons", "admin users", "FileVault", "firewall", "automatic updates", "evidence snapshots"],
            ["Verify Apple Lockdown Mode manually", "Disable unused sharing", "Restrict AirDrop", "Review trusted devices", "Review profiles and network settings", "Enable FileVault and firewall"],
            ["System Settings > Privacy & Security > Lockdown Mode", "System Settings > General > Sharing", "System Settings > Network", "System Settings > Bluetooth"],
            "Extra attack surface may remain even when Apple Lockdown Mode is enabled.",
            ["users already using Apple Lockdown Mode", "high-risk users", "government/security administrators"],
            nist_core + ["NIST SP 800-53 Rev. 5: SI-4 System Monitoring", "NIST SP 800-61 Rev. 3: Detection and Analysis"],
            ["government_nist_lockdown", "remote_access_sharing", "device_physical_access_safety"],
            [
                "Manually verify Apple Lockdown Mode status",
                "Disable Remote Login unless required",
                "Disable Screen Sharing unless required",
                "Disable File Sharing unless required",
                "Restrict AirDrop",
                "Review Bluetooth and USB devices",
                "Review installed profiles",
                "Review VPN, proxy, and DNS",
                "Review browser extensions",
                "Review unknown apps",
                "Review LaunchAgents and LaunchDaemons",
                "Review admin users",
                "Enable FileVault",
                "Enable firewall",
                "Ensure automatic security updates",
                "Preserve evidence snapshots",
                "Avoid unknown links, attachments, untrusted Wi-Fi, and delayed Apple security updates",
            ],
        ),
    ]


def category_map() -> dict[str, FamilySafetyCategory]:
    return {category.category_id: category for category in canonical_family_safety_categories()}


def new_view_state(category_id: str) -> FamilyCategoryViewState:
    return FamilyCategoryViewState(category_id=category_id, last_opened=datetime.now().isoformat(timespec="seconds"))


def reset_category_view_state(category_id: str) -> FamilyCategoryViewState:
    return new_view_state(category_id)


def reset_all_family_view_state() -> dict[str, FamilyCategoryViewState]:
    return {category.category_id: new_view_state(category.category_id) for category in canonical_family_safety_categories()}


def category_score(category: FamilySafetyCategory, statuses: list[str] | None = None) -> int:
    status_values = {
        STATUS_CONFIGURED: 1.0,
        STATUS_NEEDS_REVIEW: 0.5,
        STATUS_MANUAL: 0.5,
        STATUS_NOT_CONFIGURED: 0.0,
        STATUS_UNAVAILABLE: 0.0,
        "partially_configured": 0.5,
    }
    values = [status_values.get(status, 0.5) for status in (statuses or [category.current_status])]
    return round((sum(values) / len(values)) * 100) if values else 0


def lockdown_plus_status(score: int) -> str:
    if score >= 85:
        return "Ready"
    if score >= 65:
        return "Strengthen"
    if score >= 40:
        return "Review Required"
    return "High Exposure"
