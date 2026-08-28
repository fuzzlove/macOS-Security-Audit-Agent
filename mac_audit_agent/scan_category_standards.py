from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanStandardsMapping:
    nist: tuple[str, ...]
    cmmc: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    cisa: tuple[str, ...]
    evidence_use: str
    threat_context: str = ""


MAPPINGS: dict[str, ScanStandardsMapping] = {
    "discovery.system_identity": ScanStandardsMapping(("NIST CSF 2.0 ID.AM-02",), ("CMMC CM.L2-3.4.1",), ("T1082 System Information Discovery",), ("CISA CPG: asset inventory",), "Shows operating-system metadata available to local discovery; it does not assert attacker activity."),
    "discovery.host_identity": ScanStandardsMapping(("NIST CSF 2.0 ID.AM-02",), ("CMMC CM.L2-3.4.1",), ("T1012 Query Registry (platform-analogous configuration discovery)", "T1082 System Information Discovery"), ("CISA CPG: asset inventory",), "Shows potentially sensitive host naming metadata exposed locally."),
    "discovery.logged_on_users": ScanStandardsMapping(("NIST CSF 2.0 PR.AA-01",), ("CMMC AC.L2-3.1.1",), ("T1033 System Owner/User Discovery",), ("CISA CPG: account security",), "Shows session identity metadata visible to local processes without collecting credentials."),
    "discovery.current_account": ScanStandardsMapping(("NIST CSF 2.0 PR.AA-05",), ("CMMC AC.L2-3.1.5",), ("T1033 System Owner/User Discovery", "T1069 Permission Groups Discovery"), ("CISA CPG: least privilege",), "Supports least-privilege review of locally discoverable group membership."),
    "discovery.mounted_shares": ScanStandardsMapping(("NIST CSF 2.0 ID.AM-03",), ("CMMC AC.L2-3.1.3",), ("T1135 Network Share Discovery", "T1083 File and Directory Discovery"), ("CISA CPG: network segmentation",), "Identifies mounted data locations exposed to the current endpoint; file contents are not read."),
    "discovery.security_products": ScanStandardsMapping(("NIST CSF 2.0 PR.PS-04",), ("CMMC SI.L2-3.14.2",), ("T1518.001 Security Software Discovery",), ("CISA CPG: endpoint detection and response",), "Shows security/management extension metadata visible locally; absence is not proof of missing protection."),
    "discovery.cloud_tooling_locations": ScanStandardsMapping(("NIST CSF 2.0 ID.AM-02",), ("CMMC AC.L2-3.1.3",), ("T1083 File and Directory Discovery", "T1552.001 Credentials In Files"), ("CISA CPG: secure cloud credentials",), "Checks directory presence and permissions only; secrets and configuration contents are excluded."),
    "assurance.audit_configuration": ScanStandardsMapping(
        ("NIST SP 800-171 3.3.1", "NIST CSF 2.0 DE.CM-09"), ("CMMC AU.L2-3.3.1",),
        ("T1070 Indicator Removal", "T1562.002 Disable Windows Event Logging (analogous logging impairment coverage)"),
        ("CISA Cross-Sector CPG: centralized log collection",), "Supports review of local audit/log collection posture and logging impairment gaps.",
    ),
    "assurance.password_policy": ScanStandardsMapping(
        ("NIST SP 800-171 3.5.7", "NIST CSF 2.0 PR.AA-01"), ("CMMC IA.L2-3.5.7",),
        ("T1110 Brute Force", "T1078 Valid Accounts"), ("CISA CPG: phishing-resistant authentication",),
        "Supports account-authenticator policy evidence; it does not prove every identity provider enforces the policy.",
    ),
    "assurance.remote_services": ScanStandardsMapping(
        ("NIST SP 800-171 3.1.12", "NIST CSF 2.0 PR.AA-05"), ("CMMC AC.L2-3.1.12",),
        ("T1021 Remote Services",), ("CISA CPG: secure remote services",), "Identifies enabled sharing surfaces requiring authorization and exposure review.",
    ),
    "assurance.backup_destinations": ScanStandardsMapping(
        ("NIST SP 800-171 3.8.9", "NIST CSF 2.0 RC.RP-03"), ("CMMC MP.L2-3.8.9",),
        ("T1490 Inhibit System Recovery",), ("CISA #StopRansomware: offline and protected backups",),
        "Supports recovery-readiness evidence; destination presence does not prove recent, restorable backups.",
    ),
    "assurance.network_time": ScanStandardsMapping(
        ("NIST SP 800-171 3.3.7", "NIST CSF 2.0 DE.AE-03"), ("CMMC AU.L2-3.3.7",),
        ("T1070.006 Timestomp",), ("CISA CPG: security logging",), "Supports timestamp-correlation and audit-record integrity review.",
    ),
    "assurance.boot_arguments": ScanStandardsMapping(
        ("NIST SP 800-171 3.4.2", "NIST CSF 2.0 PR.PS-01"), ("CMMC CM.L2-3.4.2",),
        ("T1562.001 Impair Defenses",), ("CISA CPG: secure configuration",), "Surfaces boot arguments that may weaken platform protections or alter telemetry.",
    ),
    "assurance.firewall_applications": ScanStandardsMapping(
        ("NIST SP 800-171 3.13.1", "NIST CSF 2.0 PR.IR-01"), ("CMMC SC.L2-3.13.1",),
        ("T1090 Proxy", "T1041 Exfiltration Over C2 Channel"), ("CISA CPG: network segmentation and filtering",),
        "Supports review of applications explicitly registered with the macOS application firewall.",
    ),
    "assurance.install_history": ScanStandardsMapping(
        ("NIST SP 800-171 3.4.1", "NIST CSF 2.0 ID.AM-02"), ("CMMC CM.L2-3.4.1",),
        ("T1195 Supply Chain Compromise", "T1547 Boot or Logon Autostart Execution"),
        ("CISA CPG: asset inventory and vulnerability management",), "Supports software-change and asset-history review; it is not an authoritative SBOM.",
    ),
    "attack.execution.interpreter_inventory": ScanStandardsMapping(
        ("NIST CSF 2.0 DE.CM-09", "NIST SP 800-171 3.14.6"), ("CMMC SI.L2-3.14.6",),
        ("T1059 Command and Scripting Interpreter", "T1059.002 AppleScript", "T1059.004 Unix Shell", "T1059.006 Python"),
        ("CISA CPG: endpoint detection and response",),
        "Inventories expected interpreter paths for later process and code-signing correlation; presence is not suspicious.",
        "Shell, AppleScript, Python, and JavaScript execution are repeatedly documented across macOS intrusion and advanced-threat reporting.",
    ),
    "attack.execution.shell_startup_metadata": ScanStandardsMapping(
        ("NIST CSF 2.0 DE.CM-09", "NIST SP 800-171 3.4.8"), ("CMMC CM.L2-3.4.8",),
        ("T1037.004 RC Scripts", "T1546.004 Unix Shell Configuration Modification"),
        ("CISA CPG: secure configuration",),
        "Lists shell startup artifact metadata without reading script content.",
        "Shell-profile modification is a recurring persistence and execution primitive; content and intent require analyst validation.",
    ),
    "attack.persistence.background_items": ScanStandardsMapping(
        ("NIST CSF 2.0 DE.CM-09", "NIST SP 800-171 3.14.6"), ("CMMC SI.L2-3.14.6",),
        ("T1547.015 Login Items",), ("CISA CPG: endpoint detection and response",),
        "Collects macOS background-task management inventory for baseline and signer correlation.",
        "ATT&CK documents login-item use by multiple macOS malware families and advanced threat procedures; legitimate applications also use it extensively.",
    ),
    "attack.credential.keychain_locations": ScanStandardsMapping(
        ("NIST CSF 2.0 PR.DS-01", "NIST SP 800-171 3.13.16"), ("CMMC SC.L2-3.13.16",),
        ("T1555.001 Credentials from Password Stores: Keychain",), ("CISA CPG: credential security",),
        "Collects keychain location metadata only; secrets, item contents, passwords, and private keys are excluded.",
        "Keychain access is a documented objective of macOS stealers and advanced intrusion tooling; location alone is not evidence of access.",
    ),
    "attack.credential.ssh_metadata": ScanStandardsMapping(
        ("NIST CSF 2.0 PR.AA-01", "NIST SP 800-171 3.5.10"), ("CMMC IA.L2-3.5.10",),
        ("T1552.004 Private Keys", "T1098.004 SSH Authorized Keys"), ("CISA CPG: credential security",),
        "Lists bounded SSH artifact paths without reading key material.",
        "SSH keys are frequently targeted for credential access and persistence; file names do not establish compromise.",
    ),
    "attack.defense_evasion.quarantine_metadata": ScanStandardsMapping(
        ("NIST CSF 2.0 PR.PS-05", "NIST SP 800-171 3.14.2"), ("CMMC SI.L2-3.14.2",),
        ("T1553.001 Gatekeeper Bypass", "T1070 Indicator Removal"), ("CISA CPG: application allowlisting",),
        "Identifies recent download paths for separate quarantine and Gatekeeper metadata validation; contents are not read.",
        "Quarantine removal and trust-control bypass appear in macOS intrusion reporting, but a recent download is not suspicious by itself.",
    ),
    "attack.c2.proxy_state": ScanStandardsMapping(
        ("NIST CSF 2.0 DE.CM-01", "NIST SP 800-171 3.13.1"), ("CMMC SC.L2-3.13.1",),
        ("T1090 Proxy", "T1071 Application Layer Protocol"), ("CISA CPG: network segmentation and monitoring",),
        "Collects effective proxy configuration for drift and connection-context analysis.",
        "Proxy use can support command-and-control concealment, while enterprise proxies and VPN clients are common legitimate causes.",
    ),
    "attack.lateral.remote_login_state": ScanStandardsMapping(
        ("NIST CSF 2.0 PR.AA-05", "NIST SP 800-171 3.1.12"), ("CMMC AC.L2-3.1.12",),
        ("T1021.004 SSH", "T1078 Valid Accounts"), ("CISA CPG: secure remote services",),
        "Records whether Remote Login is enabled for authorization and exposure review.",
        "Remote services are common in hands-on-keyboard intrusions; enabled state alone does not show that an attacker used them.",
    ),
    "attack.impact.snapshot_inventory": ScanStandardsMapping(
        ("NIST CSF 2.0 RC.RP-03", "NIST SP 800-171 3.8.9"), ("CMMC MP.L2-3.8.9",),
        ("T1490 Inhibit System Recovery", "T1486 Data Encrypted for Impact"), ("CISA #StopRansomware: protected backups",),
        "Lists local APFS snapshot metadata as one recovery signal; it does not perform a restore test.",
        "Ransomware and destructive operations often target recovery capability; snapshot presence does not prove recoverability.",
    ),
    "attack.supply_chain.package_receipts": ScanStandardsMapping(
        ("NIST CSF 2.0 ID.AM-02", "NIST SP 800-171 3.4.1"), ("CMMC CM.L2-3.4.1",),
        ("T1195 Supply Chain Compromise",),
        ("CISA CPG: asset inventory and vulnerability management",),
        "Lists installer receipt identifiers for software provenance and change review; it is not an SBOM.",
        "Signed or trojanized software delivery has appeared in advanced campaigns; a package receipt is inventory evidence, not a compromise verdict.",
    ),
    "attack.collection.external_storage": ScanStandardsMapping(
        ("NIST CSF 2.0 ID.AM-03", "NIST SP 800-171 3.8.7"), ("CMMC MP.L2-3.8.7",),
        ("T1025 Data from Removable Media", "T1052 Exfiltration Over Physical Medium"), ("CISA CPG: asset inventory",),
        "Collects attached storage layout metadata without reading volume contents.",
        "Removable storage can support collection or exfiltration but is also routine; authorization and event timing determine risk.",
    ),
}


def mapping_for(command_id: str) -> ScanStandardsMapping | None:
    return MAPPINGS.get(command_id)


def render_mapping(command_id: str) -> str:
    mapping = mapping_for(command_id)
    if mapping is None:
        return "No command-specific crosswalk is registered. Findings may still map through the report framework engine."
    return "\n".join((
        "NIST: " + ", ".join(mapping.nist),
        "CMMC support: " + ", ".join(mapping.cmmc),
        "MITRE ATT&CK coverage: " + ", ".join(mapping.mitre_attack),
        "CISA guidance: " + ", ".join(mapping.cisa),
        "Evidence use: " + mapping.evidence_use,
        *(('Threat context: ' + mapping.threat_context,) if mapping.threat_context else ()),
        "Qualification: supporting evidence only; this is not certification and not proof that an ATT&CK technique occurred.",
    ))


__all__ = ["MAPPINGS", "ScanStandardsMapping", "mapping_for", "render_mapping"]
