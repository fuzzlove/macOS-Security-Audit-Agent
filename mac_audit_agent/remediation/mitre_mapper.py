from __future__ import annotations

from typing import Any

from mac_audit_agent.remediation.finding_taxonomy import normalize_finding_type
from mac_audit_agent.remediation.models import SourceMapping


TECHNIQUE_MAP: dict[str, list[dict[str, str]]] = {
    "new_launch_agent": [{"technique_id": "T1543.001", "name": "Launch Agent", "confidence": "partial"}],
    "unsigned_launch_agent": [{"technique_id": "T1543.001", "name": "Launch Agent", "confidence": "partial"}],
    "new_launch_daemon": [{"technique_id": "T1543.004", "name": "Launch Daemon", "confidence": "partial"}],
    "unsigned_launch_daemon": [{"technique_id": "T1543.004", "name": "Launch Daemon", "confidence": "partial"}],
    "suspicious_persistence": [{"technique_id": "T1543", "name": "Create or Modify System Process", "confidence": "partial"}],
    "hidden_localhost_port": [{"technique_id": "T1090", "name": "Proxy", "confidence": "manual_review_required"}],
    "suspicious_network_connection": [{"technique_id": "T1071", "name": "Application Layer Protocol", "confidence": "manual_review_required"}],
    "new_listening_port": [{"technique_id": "T1105", "name": "Ingress Tool Transfer", "confidence": "manual_review_required"}],
    "admin_user_change": [{"technique_id": "T1098", "name": "Account Manipulation", "confidence": "partial"}],
    "sudoers_change": [{"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "confidence": "partial"}],
    "remote_login_enabled": [{"technique_id": "T1021.004", "name": "SSH", "confidence": "partial"}],
    "screen_sharing_enabled": [{"technique_id": "T1021", "name": "Remote Services", "confidence": "partial"}],
    "gatekeeper_disabled": [{"technique_id": "T1553", "name": "Subvert Trust Controls", "confidence": "partial"}],
    "suspected_malware_or_threat_activity": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter", "confidence": "manual_review_required"}],
}

MITIGATION_MAP: dict[str, list[str]] = {
    "T1543.001": ["Audit LaunchAgent paths and ownership.", "Restrict write access to user and system launch paths.", "Monitor persistence changes."],
    "T1543.004": ["Require administrator approval for LaunchDaemon changes.", "Audit root-owned plist permissions.", "Monitor persistence changes."],
    "T1543": ["Monitor launch services and persistence directories.", "Apply least privilege and configuration management."],
    "T1090": ["Inspect proxy/listener behavior.", "Restrict unauthorized local proxy services.", "Monitor network connections."],
    "T1071": ["Monitor unusual application-layer traffic.", "Restrict unauthorized outbound connections where policy supports it."],
    "T1105": ["Monitor unexpected listeners and file-transfer patterns.", "Restrict exposed services."],
    "T1098": ["Review account changes.", "Use least privilege.", "Monitor administrative group membership."],
    "T1548": ["Review privilege elevation configuration.", "Limit sudo/admin rights.", "Monitor changes to privileged configuration files."],
    "T1021.004": ["Restrict SSH access.", "Use strong authentication.", "Monitor remote logins."],
    "T1021": ["Restrict remote service access.", "Monitor remote sessions.", "Disable unneeded services."],
    "T1553": ["Keep trust controls enabled.", "Review code signatures and notarization.", "Monitor trust-setting changes."],
    "T1059": ["Review script execution context.", "Restrict untrusted scripts.", "Preserve process and command-line evidence."],
}


def map_finding_to_attack_techniques(finding: dict[str, Any]) -> list[dict[str, str]]:
    return list(TECHNIQUE_MAP.get(normalize_finding_type(finding), []))


def map_technique_to_mitigations(technique_id: str) -> list[str]:
    return list(MITIGATION_MAP.get(technique_id, ["Manual ATT&CK mitigation review required."]))


def generate_mitre_examination_steps(finding: dict[str, Any]) -> list[str]:
    techniques = map_finding_to_attack_techniques(finding)
    if not techniques:
        return []
    return [
        f"Review whether this finding is consistent with possible ATT&CK technique {item['technique_id']} ({item['name']}); mapping is analytic context, not proof of adversary activity."
        for item in techniques
    ]


def generate_mitre_mitigation_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    techniques = map_finding_to_attack_techniques(finding)
    mitigations = []
    mappings = []
    for technique in techniques:
        mitigations.extend(map_technique_to_mitigations(technique["technique_id"]))
        mappings.append(
            SourceMapping(
                source_type="MITRE_ATTACK",
                source_id=technique["technique_id"],
                source_url=f"https://attack.mitre.org/techniques/{technique['technique_id'].replace('.', '/')}/",
                source_version="ATT&CK Enterprise public reference",
                mapping_confidence="partial" if technique.get("confidence") == "partial" else "manual_review_required",
                notes="ATT&CK mapping is defensive analytic context and does not identify a threat actor.",
            ).to_dict()
        )
    return {
        "techniques": techniques,
        "mitigations": sorted(set(mitigations)),
        "source_mappings": mappings,
        "limitations": ["MITRE ATT&CK mapping is not proof of adversary activity or actor attribution."] if techniques else [],
    }
