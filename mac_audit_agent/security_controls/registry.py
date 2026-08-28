from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityControlDefinition:
    control_id: str
    name: str
    category: str
    sensitive_paths: tuple[str, ...]
    response_guidance: tuple[str, ...]
    attack_mappings: tuple[str, ...] = ()
    requires_full_disk_access: bool = False
    requires_endpoint_security_for_attribution: bool = True


def _control(control_id: str, name: str, category: str, paths: tuple[str, ...], guidance: tuple[str, ...], attacks: tuple[str, ...] = ()) -> SecurityControlDefinition:
    return SecurityControlDefinition(control_id, name, category, paths, guidance, attacks)


CONTROL_REGISTRY = {
    item.control_id: item for item in (
        _control("macos.sip", "System Integrity Protection", "system_integrity", (), ("Validate Recovery-mode maintenance authorization.", "Preserve evidence before remediation."), ("T1562.001",)),
        _control("macos.gatekeeper", "Gatekeeper and Application Assessment", "application_assessment", ("/Library/Preferences/com.apple.security.plist",), ("Review the responsible process and policy database changes.",), ("T1553.001",)),
        _control("macos.filevault", "FileVault", "disk_encryption", ("/Library/Preferences/com.apple.fdesetup.plist",), ("Confirm encryption policy and authorized operator; never collect recovery keys.",), ("T1562.001",)),
        _control("macos.application_firewall", "macOS Application Firewall", "network_security", ("/Library/Preferences/com.apple.alf.plist",), ("Review state, application exceptions, and responsible process.",), ("T1562.004",)),
        _control("macos.packet_filter", "Packet Filter", "network_security", ("/etc/pf.conf", "/etc/pf.anchors"), ("Validate rules without overwriting administrator policy.",), ("T1562.004",)),
        _control("macos.remote_access", "Remote Access and Sharing", "remote_access", ("/etc/ssh", "/Library/Preferences/com.apple.RemoteManagement.plist"), ("Validate maintenance authorization.", "Review SSH keys, sessions, and listening services."), ("T1021.004",)),
        _control("macos.tcc", "Privacy and Transparency Consent Control", "privacy", ("/Library/Application Support/com.apple.TCC",), ("Report reduced visibility; do not manipulate protected databases.",), ("T1548",)),
        _control("macos.accounts", "Authentication and Account Security", "identity", ("/etc/sudoers", "/etc/pam.d", "/var/db/dslocal/nodes/Default/users"), ("Review account, administrator membership, and authorization policy changes.",), ("T1136.001",)),
        _control("macos.persistence", "Persistence and Startup Security", "persistence", ("/Library/LaunchAgents", "/Library/LaunchDaemons"), ("Review signing identity, origin, and intended persistence.",), ("T1543.001",)),
        _control("macos.security_updates", "Security Update and Malware Protection", "updates", ("/Library/Preferences/com.apple.SoftwareUpdate.plist",), ("Review disabled services and update-policy changes.",), ("T1562.001",)),
        _control("macos.network_configuration", "Network and DNS Security", "network_configuration", ("/etc/hosts", "/etc/resolver"), ("Review DNS, proxy, route, certificate, and interface changes.",), ("T1557",)),
        _control("msaa.monitoring_integrity", "MSAA Monitoring and Audit Controls", "self_protection", (), ("Preserve the affected artifact.", "Restore monitoring only after evidence capture and authorization review."), ("T1562.001",)),
    )
}
