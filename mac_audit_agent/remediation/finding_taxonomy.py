from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


FINDING_TYPES = {
    "vulnerability_cve",
    "cisa_kev_vulnerability",
    "apple_security_update_gap",
    "unsigned_binary",
    "unsigned_launch_agent",
    "unsigned_launch_daemon",
    "suspicious_persistence",
    "new_launch_agent",
    "new_launch_daemon",
    "new_privileged_helper",
    "suspicious_network_connection",
    "new_listening_port",
    "hidden_localhost_port",
    "dns_gateway_change",
    "vpn_change",
    "new_usb_device",
    "unknown_hid_device",
    "usb_storage_device",
    "bluetooth_device",
    "admin_user_change",
    "sudoers_change",
    "remote_login_enabled",
    "screen_sharing_enabled",
    "tcc_privacy_change",
    "gatekeeper_disabled",
    "firewall_disabled",
    "filevault_disabled",
    "sip_disabled",
    "secure_boot_weak_or_unknown",
    "apple_diagnostic_hardware_issue",
    "possible_false_positive",
    "emerging_ttp_no_cve",
    "suspected_malware_or_threat_activity",
    "unknown_unsigned_behavior",
    "unknown",
}


@dataclass(frozen=True)
class FindingTypeGuidance:
    finding_type: str
    examination_steps: list[str] = field(default_factory=list)
    remediation_actions: list[str] = field(default_factory=list)
    evidence_checklist: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    standards_context: list[str] = field(default_factory=list)
    apple_evidence_needs: list[str] = field(default_factory=list)
    skill_level: str = "analyst"


DEFAULT_GUIDANCE = FindingTypeGuidance(
    finding_type="unknown",
    examination_steps=[
        "Review the finding evidence, command/source, timestamp, affected path, user, process, and network context.",
        "Compare the observation to a known-good baseline or expected administrative activity.",
    ],
    remediation_actions=[
        "Manual review required. Preserve evidence before making system changes.",
        "If confirmed, remediate using the vendor or system-owner approved procedure.",
    ],
    evidence_checklist=[
        "Finding JSON and report excerpt",
        "Command/source that produced the finding",
        "Affected file, process, account, network endpoint, or configuration value",
    ],
    false_positive_checks=[
        "Confirm the item is not expected management software, developer tooling, an updater, or a user-approved configuration.",
        "Verify file path, ownership, signature/notarization status, and installation source where applicable.",
    ],
    standards_context=["NIST CSF Detect", "NIST SP 800-53 AU/SI manual review"],
    apple_evidence_needs=["MSAA finding excerpt", "macOS version/build", "reproduction notes if the behavior appears Apple/macOS related"],
)


TAXONOMY: dict[str, FindingTypeGuidance] = {
    "vulnerability_cve": FindingTypeGuidance(
        "vulnerability_cve",
        ["Verify the CVE applies to the installed product, version, architecture, and local exposure path."],
        ["Update, patch, remove, or apply the vendor mitigation for the affected component."],
        ["CVE ID", "Affected product/path/version", "Vendor advisory", "Installed version after remediation"],
        ["Confirm the detected version is actually installed and vulnerable.", "Check whether the vendor backported the fix without changing the visible version."],
        standards_context=["NVD CVE/CVSS", "CISA CPG vulnerability management", "NIST CSF Protect/Detect"],
        apple_evidence_needs=["Affected component version", "macOS build", "security update state"],
        skill_level="administrator",
    ),
    "cisa_kev_vulnerability": FindingTypeGuidance(
        "cisa_kev_vulnerability",
        ["Confirm local applicability and exposure; KEV means known exploitation exists for the vulnerability, not compromise of this Mac."],
        ["Prioritize vendor remediation or mitigation and document completion or exception."],
        ["CVE ID", "CISA KEV action", "Due date", "Local affected version", "Remediation evidence"],
        ["Confirm the CVE ID and product match CISA KEV details."],
        standards_context=["CISA KEV", "CISA CPG vulnerability management", "NIST SI/CM"],
        skill_level="administrator",
    ),
    "apple_security_update_gap": FindingTypeGuidance(
        "apple_security_update_gap",
        ["Verify macOS build, model support, update channel, and whether the update applies to this Mac."],
        ["Apply the relevant Apple security update or document why the Mac is not eligible."],
        ["macOS version/build", "Software Update state", "Apple advisory reference", "Post-update version/build"],
        ["Confirm the advisory applies to the detected macOS version and hardware model."],
        standards_context=["Apple security updates", "NIST SI-2 flaw remediation"],
        apple_evidence_needs=["macOS build", "Software Update output", "reproduction or exposure notes"],
        skill_level="beginner",
    ),
    "suspicious_persistence": FindingTypeGuidance(
        "suspicious_persistence",
        ["Inspect plist label, program arguments, owner, permissions, signature, notarization, and first-seen timestamp."],
        ["Disable or remove only after preserving the plist and referenced binary for review."],
        ["LaunchAgent/LaunchDaemon plist", "Referenced binary hash/signature", "Owner/permissions", "Unified log excerpts"],
        ["Confirm it is not expected vendor software, MDM tooling, backup software, or user login tooling."],
        ["T1543.001", "T1543.004"],
        ["MITRE ATT&CK Persistence", "NIST CM/AU/SI"],
        ["plist copy", "binary hash", "unified logs"],
    ),
    "new_launch_agent": FindingTypeGuidance(
        "new_launch_agent",
        ["Review the LaunchAgent path, label, ProgramArguments, RunAtLoad/KeepAlive keys, and signer."],
        ["If unexpected, unload/disable through launchctl after evidence preservation and owner review."],
        ["LaunchAgent plist", "referenced binary", "file hash", "first seen timestamp"],
        ["Confirm expected app installation or update activity."],
        ["T1543.001"],
        ["MITRE ATT&CK Persistence", "NIST CM-3"],
        ["plist copy", "related logs"],
    ),
    "new_launch_daemon": FindingTypeGuidance(
        "new_launch_daemon",
        ["Review the LaunchDaemon path, label, program, owner root/wheel expectation, permissions, and signer."],
        ["If unexpected, disable through launchctl with admin approval after evidence preservation."],
        ["LaunchDaemon plist", "referenced binary", "owner/permissions", "hash/signature"],
        ["Confirm MDM, security tool, VPN, backup, or vendor installer activity."],
        ["T1543.004"],
        ["MITRE ATT&CK Persistence", "NIST CM-3"],
        ["plist copy", "system log excerpts"],
        "administrator",
    ),
    "hidden_localhost_port": FindingTypeGuidance(
        "hidden_localhost_port",
        ["Identify the listening process, parent process, launch source, binary signer, and local clients connecting to the port."],
        ["Stop or block only after confirming the port is not required by a legitimate local app or service."],
        ["lsof/netstat output", "process details", "binary hash/signature", "launch item", "timeframe logs"],
        ["Confirm expected developer server, browser helper, sync agent, security tool, or Apple service."],
        ["T1090"],
        ["MITRE ATT&CK Command and Control analytic context", "NIST SC/AU/SI"],
        ["network snapshot", "process sample instructions"],
    ),
    "suspicious_network_connection": FindingTypeGuidance(
        "suspicious_network_connection",
        ["Review local process, remote endpoint, DNS name, signer, user, and connection timing."],
        ["Contain or block only when the process and endpoint are confirmed unwanted or risky."],
        ["connection record", "process metadata", "DNS/cache context", "packet capture metadata if collected"],
        ["Confirm expected updater, VPN, browser, collaboration app, or managed security tool traffic."],
        ["T1071"],
        ["MITRE ATT&CK Command and Control analytic context", "NIST SC-7"],
        ["network diagnostics summary", "reproduction timeframe"],
    ),
    "admin_user_change": FindingTypeGuidance(
        "admin_user_change",
        ["Confirm who created or modified the admin account and whether the change aligns with approved access management."],
        ["Remove unauthorized admin rights or account after preserving account-change evidence."],
        ["user list", "admin group membership", "timestamp", "Unified log account-management entries"],
        ["Confirm expected IT support, MDM enrollment, migration assistant, or user-approved change."],
        ["T1098"],
        ["MITRE ATT&CK Account Manipulation", "NIST AC/AU"],
        ["account state", "logs around change time"],
        "administrator",
    ),
    "remote_login_enabled": FindingTypeGuidance(
        "remote_login_enabled",
        ["Confirm whether SSH is intentionally enabled, who can access it, and whether the Mac is reachable from untrusted networks."],
        ["Disable Remote Login if not required; if required, restrict users and require strong authentication."],
        ["systemsetup state", "allowed users", "network exposure", "auth logs"],
        ["Confirm expected IT administration or developer workflow."],
        ["T1021.004"],
        ["MITRE ATT&CK Remote Services", "NIST AC/SC"],
        ["sharing settings", "auth log excerpts"],
    ),
    "screen_sharing_enabled": FindingTypeGuidance(
        "screen_sharing_enabled",
        ["Confirm whether Screen Sharing/Remote Management is approved and which users can connect."],
        ["Disable if not required; otherwise restrict access and monitor remote session activity."],
        ["sharing settings", "allowed users", "remote session logs"],
        ["Confirm expected support, MDM, or accessibility workflow."],
        ["T1021"],
        ["MITRE ATT&CK Remote Services", "NIST AC/SC"],
        ["sharing settings", "session logs"],
    ),
    "gatekeeper_disabled": FindingTypeGuidance(
        "gatekeeper_disabled",
        ["Verify Gatekeeper state and determine why it was changed."],
        ["Re-enable Gatekeeper unless a documented, temporary exception is approved."],
        ["spctl status", "configuration change evidence"],
        ["Confirm temporary developer testing or approved software deployment exception."],
        ["T1553"],
        ["MITRE ATT&CK Subvert Trust Controls", "NIST SI/CM"],
        ["security settings state"],
        "administrator",
    ),
    "firewall_disabled": FindingTypeGuidance(
        "firewall_disabled",
        ["Verify application firewall state and evaluate network exposure."],
        ["Enable the macOS firewall unless a documented network control supersedes it."],
        ["firewall state", "listening ports", "network profile"],
        ["Confirm managed network controls or temporary troubleshooting exception."],
        standards_context=["NIST SC-7 boundary protection", "CISA CPG security configuration"],
        apple_evidence_needs=["firewall state", "network context"],
    ),
    "filevault_disabled": FindingTypeGuidance(
        "filevault_disabled",
        ["Confirm FileVault state, hardware support, and organizational encryption requirements."],
        ["Enable FileVault where appropriate after recovery key planning."],
        ["FileVault state", "recovery key handling note", "user/admin approval"],
        ["Confirm device is ephemeral, lab-only, or protected by an approved compensating control."],
        standards_context=["NIST MP/SC protection", "CISA CPG security configuration"],
        skill_level="administrator",
    ),
    "new_usb_device": FindingTypeGuidance(
        "new_usb_device",
        ["Review device identity, class, vendor/product IDs, serial, first seen time, and user confirmation."],
        ["Remove and quarantine unknown high-risk devices until reviewed."],
        ["USB inventory", "device class", "vendor/product/serial", "timestamp"],
        ["Confirm expected keyboard, mouse, storage, dock, camera, or phone connection."],
        standards_context=["NIST MP media protection", "CISA CPG logging"],
        apple_evidence_needs=["USB inventory", "hardware context"],
    ),
    "unknown_hid_device": FindingTypeGuidance(
        "unknown_hid_device",
        ["Confirm physical presence and identity of the input device."],
        ["Disconnect unknown HID devices until ownership and purpose are confirmed."],
        ["HID inventory", "timestamp", "device identity", "user statement"],
        ["Confirm expected keyboard, mouse, trackpad, accessibility device, or dock component."],
        standards_context=["NIST MP/AC physical media and access context"],
        apple_evidence_needs=["USB/Bluetooth inventory"],
    ),
    "bluetooth_device": FindingTypeGuidance(
        "bluetooth_device",
        ["Review Bluetooth device identity, pairing state, class, and user confirmation."],
        ["Forget or disconnect unknown Bluetooth devices after evidence capture."],
        ["Bluetooth inventory", "pairing status", "timestamp"],
        ["Confirm expected peripherals, headphones, phone, or continuity device."],
        apple_evidence_needs=["Bluetooth inventory", "Wireless Diagnostics guidance if connectivity issue"],
    ),
    "apple_diagnostic_hardware_issue": FindingTypeGuidance(
        "apple_diagnostic_hardware_issue",
        ["Record Apple Diagnostics reference code and correlate with observed MSAA finding evidence."],
        ["Use Apple Support or service workflow; MSAA should not attempt hardware remediation."],
        ["Apple Diagnostics reference code", "hardware model", "reproduction notes", "MSAA evidence excerpt"],
        ["Confirm the code was captured from this Mac and after relevant peripherals were disconnected where appropriate."],
        standards_context=["Apple Diagnostics public support workflow"],
        apple_evidence_needs=["hardware summary", "reference code", "USB/Bluetooth inventory"],
        skill_level="beginner",
    ),
    "emerging_ttp_no_cve": FindingTypeGuidance(
        "emerging_ttp_no_cve",
        ["Preserve evidence and review behavior chain before assigning labels or remediation scope."],
        ["Contain confirmed unwanted behavior using local defensive controls; do not claim CVE or actor attribution without source correlation."],
        ["timeline", "process tree", "file hashes", "network endpoints", "logs", "user activity context"],
        ["Rule out benign admin tools, security tools, developer tools, and expected app behavior."],
        standards_context=["MITRE ATT&CK analytic context", "NIST IR/AU/SI"],
        apple_evidence_needs=["finding package", "reproduction notes if Apple platform behavior is suspected"],
        skill_level="advanced",
    ),
    "suspected_malware_or_threat_activity": FindingTypeGuidance(
        "suspected_malware_or_threat_activity",
        ["Preserve evidence, isolate if necessary, and perform analyst triage before cleanup."],
        ["Contain the affected account/process/network path and remediate confirmed malicious artifacts using approved IR procedures."],
        ["timeline", "process tree", "file hashes", "network endpoints", "persistence items", "logs"],
        ["Rule out approved security testing, MDM tooling, developer workflows, and known vendor behavior."],
        standards_context=["NIST IR lifecycle", "MITRE ATT&CK analytic context"],
        apple_evidence_needs=["security/vulnerability evidence package if Apple issue is suspected"],
        skill_level="advanced",
    ),
}

for alias in [
    "unsigned_binary",
    "unknown_unsigned_behavior",
    "unsigned_launch_agent",
    "unsigned_launch_daemon",
    "new_privileged_helper",
    "new_listening_port",
    "dns_gateway_change",
    "vpn_change",
    "usb_storage_device",
    "sudoers_change",
    "tcc_privacy_change",
    "sip_disabled",
    "secure_boot_weak_or_unknown",
    "possible_false_positive",
]:
    TAXONOMY.setdefault(alias, DEFAULT_GUIDANCE)


def _text(finding: dict[str, Any]) -> str:
    return " ".join(str(finding.get(key, "")) for key in ("finding_type", "category", "title", "description", "evidence", "event_type", "rule_id")).lower()


def cve_ids_from_finding(finding: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for key in ("cve_ids", "cve_refs"):
        value = finding.get(key)
        if isinstance(value, list):
            ids.extend(str(item).upper() for item in value if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(item).upper()))
        elif isinstance(value, str):
            ids.extend(re.findall(r"CVE-\d{4}-\d{4,}", value.upper()))
    ids.extend(re.findall(r"CVE-\d{4}-\d{4,}", _text(finding).upper()))
    return sorted(set(ids))


def normalize_finding_type(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("finding_type", "")).lower().strip()
    if explicit in FINDING_TYPES:
        return explicit
    text = _text(finding)
    if cve_ids_from_finding(finding):
        return "cisa_kev_vulnerability" if finding.get("kev") or "kev" in text else "vulnerability_cve"
    checks = [
        ("apple_security_update_gap", ["apple security", "software update", "security update gap"]),
        ("unsigned_launch_agent", ["unsigned launchagent", "unsigned launch agent"]),
        ("unsigned_launch_daemon", ["unsigned launchdaemon", "unsigned launch daemon"]),
        ("unsigned_binary", ["unsigned binary", "unsigned process", "not signed"]),
        ("new_launch_agent", ["launchagent", "launch agent"]),
        ("new_launch_daemon", ["launchdaemon", "launch daemon"]),
        ("suspicious_persistence", ["persistence", "login item"]),
        ("hidden_localhost_port", ["hidden localhost", "localhost port"]),
        ("new_listening_port", ["listening port", "new listener"]),
        ("suspicious_network_connection", ["network connection", "outbound connection", "inbound connection"]),
        ("dns_gateway_change", ["dns", "gateway"]),
        ("vpn_change", ["vpn"]),
        ("unknown_hid_device", ["hid", "keyboard", "mouse"]),
        ("usb_storage_device", ["usb storage"]),
        ("new_usb_device", ["usb"]),
        ("bluetooth_device", ["bluetooth"]),
        ("admin_user_change", ["admin user", "administrator", "privilege"]),
        ("sudoers_change", ["sudoers", "sudo"]),
        ("remote_login_enabled", ["remote login", "ssh"]),
        ("screen_sharing_enabled", ["screen sharing", "remote management"]),
        ("tcc_privacy_change", ["tcc", "privacy permission"]),
        ("gatekeeper_disabled", ["gatekeeper", "spctl"]),
        ("firewall_disabled", ["firewall"]),
        ("filevault_disabled", ["filevault"]),
        ("sip_disabled", ["sip disabled", "system integrity protection"]),
        ("secure_boot_weak_or_unknown", ["secure boot"]),
        ("apple_diagnostic_hardware_issue", ["apple diagnostics", "hardware issue"]),
        ("suspected_malware_or_threat_activity", ["malware", "threat activity", "reverse shell"]),
        ("emerging_ttp_no_cve", ["emerging", "ttp", "unclassified"]),
    ]
    for finding_type, needles in checks:
        if any(needle in text for needle in needles):
            return finding_type
    return "unknown"


def taxonomy_for_finding(finding: dict[str, Any]) -> FindingTypeGuidance:
    return TAXONOMY.get(normalize_finding_type(finding), DEFAULT_GUIDANCE)
