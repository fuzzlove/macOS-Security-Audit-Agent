from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any


SUPPORTED_FRAMEWORKS = {
    "NIST_CSF_2_0",
    "NIST_800_53_REV5",
    "NIST_800_61_REV3",
    "MITRE_ATTACK_MACOS",
    "CISA_KEV",
    "NVD_CVE",
}

NIST_CSF_FUNCTIONS = {"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}
NIST_800_61_PHASES = {"Preparation", "Detection and Analysis", "Containment, Eradication, and Recovery", "Post-Incident Activity"}


@dataclass(frozen=True)
class FrameworkMapping:
    framework: str
    id: str
    name: str
    category: str
    description: str
    relevance: str
    confidence: str
    evidence_required: list[str]
    reference_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _mapping(
    framework: str,
    mapping_id: str,
    name: str,
    category: str,
    description: str,
    relevance: str,
    confidence: str = "medium",
    evidence_required: list[str] | None = None,
    reference_url: str = "",
) -> FrameworkMapping:
    return FrameworkMapping(
        framework=framework,
        id=mapping_id,
        name=name,
        category=category,
        description=description,
        relevance=relevance,
        confidence=confidence,
        evidence_required=evidence_required or [],
        reference_url=reference_url,
    )


def nist_csf(function: str, category: str, name: str, relevance: str, confidence: str = "medium") -> FrameworkMapping:
    return _mapping(
        "NIST_CSF_2_0",
        category,
        name,
        function,
        f"NIST Cybersecurity Framework 2.0 {function} function mapping.",
        relevance,
        confidence,
        ["finding category", "detector source", "local evidence summary"],
        "https://www.nist.gov/cyberframework",
    )


def nist_800_53(control_id: str, name: str, relevance: str, confidence: str = "medium") -> FrameworkMapping:
    return _mapping(
        "NIST_800_53_REV5",
        control_id,
        name,
        control_id.split("-")[0],
        "NIST SP 800-53 Rev. 5 security and privacy control mapping.",
        relevance,
        confidence,
        ["local observation", "audit evidence", "review notes"],
        f"https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#/control?version=5.1&number={control_id}",
    )


def nist_800_61(phase: str, relevance: str, confidence: str = "medium") -> FrameworkMapping:
    return _mapping(
        "NIST_800_61_REV3",
        phase,
        phase,
        "Incident Response Lifecycle",
        "NIST incident response lifecycle mapping for analyst workflow context.",
        relevance,
        confidence,
        ["event timeline", "analysis notes", "evidence preservation status"],
        "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    )


def mitre(technique_id: str, name: str, tactic: str, relevance: str, confidence: str = "medium") -> FrameworkMapping:
    return _mapping(
        "MITRE_ATTACK_MACOS",
        technique_id,
        name,
        tactic,
        "MITRE ATT&CK Enterprise macOS technique mapping.",
        relevance,
        confidence,
        ["process/path evidence", "event timeline", "detector context"],
        f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


def cisa_kev(cve_id: str, relevance: str, confidence: str = "high") -> FrameworkMapping:
    return _mapping(
        "CISA_KEV",
        cve_id,
        "CISA Known Exploited Vulnerabilities reference",
        "Vulnerability Management",
        "CISA KEV catalog reference where the CVE appears in known exploited vulnerability data.",
        relevance,
        confidence,
        ["CVE identifier", "KEV match metadata"],
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )


def nvd_cve(cve_id: str, relevance: str, confidence: str = "high") -> FrameworkMapping:
    return _mapping(
        "NVD_CVE",
        cve_id,
        "NVD CVE reference",
        "Vulnerability Management",
        "NVD/CVE reference for vulnerability assessment context.",
        relevance,
        confidence,
        ["CVE identifier", "affected product/version", "CVSS metadata when available"],
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


MITRE_BY_TECHNIQUE = {
    "T1543.004": ("Launch Daemon", "Persistence"),
    "T1543.001": ("Launch Agent", "Persistence"),
    "T1037": ("Boot or Logon Initialization Scripts", "Persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1547.015": ("Login Items", "Persistence"),
    "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1204": ("User Execution", "Execution"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1200": ("Hardware Additions", "Initial Access"),
}


CATEGORY_BASE_MAPPINGS: dict[str, list[FrameworkMapping]] = {
    "persistence": [
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports detection of persistence-relevant local changes.", "high"),
        nist_csf("Respond", "RS.AN", "Analysis", "Supports analysis of persistence changes during response.", "high"),
        nist_800_53("SI-4", "System Monitoring", "Maps local persistence monitoring to system monitoring review.", "high"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of audit records and event evidence.", "high"),
        nist_800_53("CM-3", "Configuration Change Control", "Maps launch and startup changes to configuration change review.", "medium"),
        nist_800_53("CM-6", "Configuration Settings", "Supports review of local configuration settings.", "medium"),
        nist_800_61("Detection and Analysis", "Supports incident detection and analysis of persistence indicators.", "high"),
        mitre("T1547", "Boot or Logon Autostart Execution", "Persistence", "Applies to startup or login persistence indicators.", "medium"),
    ],
    "identity": [
        nist_csf("Protect", "PR.AA", "Identity Management, Authentication, and Access Control", "Supports review of account and privilege changes.", "high"),
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of user and administrator changes.", "high"),
        nist_800_53("AC-2", "Account Management", "Maps local account changes to account management review.", "high"),
        nist_800_53("AC-6", "Least Privilege", "Supports review of administrative privilege changes.", "high"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of account-related audit evidence.", "medium"),
        nist_800_61("Detection and Analysis", "Supports analysis of account change events.", "medium"),
        mitre("T1078", "Valid Accounts", "Defense Evasion", "Applies when valid local accounts or privileges are involved.", "medium"),
    ],
    "network": [
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of connections, listeners, and localhost exposure.", "high"),
        nist_csf("Respond", "RS.AN", "Analysis", "Supports triage of network findings during response.", "medium"),
        nist_800_53("SI-4", "System Monitoring", "Maps listener and connection visibility to system monitoring.", "high"),
        nist_800_53("SC-7", "Boundary Protection", "Supports review of network boundaries and exposed services.", "medium"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of network evidence.", "medium"),
        nist_800_61("Detection and Analysis", "Supports incident analysis of network activity.", "high"),
        mitre("T1046", "Network Service Discovery", "Discovery", "Applies to service discovery and listener review.", "medium"),
    ],
    "hardware": [
        nist_csf("Identify", "ID.AM", "Asset Management", "Supports inventory and review of attached devices.", "high"),
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of hardware inventory changes.", "high"),
        nist_800_53("CM-8", "System Component Inventory", "Maps device inventory changes to component inventory review.", "high"),
        nist_800_53("MP-7", "Media Use", "Relevant for removable media and device use review.", "medium"),
        nist_800_61("Detection and Analysis", "Supports analysis of physical device events.", "medium"),
        mitre("T1200", "Hardware Additions", "Initial Access", "Applies where unexpected hardware may affect system trust.", "medium"),
    ],
    "session": [
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of local session and physical activity signals.", "high"),
        nist_csf("Respond", "RS.AN", "Analysis", "Supports analysis of user presence and session context.", "medium"),
        nist_800_53("AU-6", "Audit Record Review", "Maps session evidence to audit review.", "medium"),
        nist_800_53("PE-3", "Physical Access Control", "Relevant as context for physical access review.", "low"),
        nist_800_61("Detection and Analysis", "Supports analysis of physical/session activity during incident review.", "medium"),
    ],
    "execution": [
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of process execution evidence.", "high"),
        nist_csf("Respond", "RS.AN", "Analysis", "Supports response analysis of suspicious execution.", "high"),
        nist_800_53("SI-4", "System Monitoring", "Maps execution monitoring to system monitoring.", "high"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of execution evidence.", "medium"),
        nist_800_61("Detection and Analysis", "Supports incident analysis of execution evidence.", "high"),
        mitre("T1059", "Command and Scripting Interpreter", "Execution", "Applies to command and script execution indicators.", "medium"),
    ],
    "privacy": [
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports monitoring of privacy-sensitive device usage.", "medium"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of privacy-related local events.", "medium"),
        nist_800_61("Detection and Analysis", "Supports analysis of potentially suspicious device use.", "medium"),
    ],
    "monitoring": [
        nist_csf("Govern", "GV.OV", "Oversight", "Supports oversight of monitoring health and coverage.", "medium"),
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports continuous monitoring coverage assessment.", "high"),
        nist_800_53("CA-7", "Continuous Monitoring", "Maps monitor coverage and health to continuous monitoring.", "high"),
        nist_800_53("SI-4", "System Monitoring", "Supports system monitoring health review.", "high"),
    ],
    "integrity": [
        nist_csf("Protect", "PR.PS", "Platform Security", "Supports review of protected monitor integrity.", "high"),
        nist_csf("Detect", "DE.CM", "Continuous Monitoring", "Supports detection of integrity changes.", "high"),
        nist_800_53("SI-7", "Software, Firmware, and Information Integrity", "Maps integrity checks to software integrity review.", "high"),
        nist_800_53("CM-5", "Access Restrictions for Change", "Supports review of protected configuration changes.", "medium"),
        mitre("T1562", "Impair Defenses", "Defense Evasion", "Applies when monitoring or defenses appear modified.", "medium"),
    ],
    "provenance": [
        nist_csf("Govern", "GV.OV", "Oversight", "Supports review of alert quality and provenance.", "medium"),
        nist_csf("Detect", "DE.AE", "Adverse Event Analysis", "Supports event analysis and false-positive management.", "medium"),
        nist_800_53("AU-6", "Audit Record Review", "Supports review of alert records and evidence trails.", "medium"),
    ],
}

FINDING_CATEGORY_ALIASES = {
    "localhost port scan": "network",
    "network": "network",
    "ports": "network",
    "persistence": "persistence",
    "accounts & privileges": "identity",
    "ssh": "identity",
    "processes": "execution",
    "execution": "execution",
    "shell history": "execution",
    "permissions": "integrity",
    "file/directory issues": "integrity",
    "baseline comparison": "provenance",
    "system information": "monitoring",
    "network discovery": "network",
    "macos security": "integrity",
}


def normalize_category(category: str) -> str:
    return FINDING_CATEGORY_ALIASES.get(str(category or "").strip().lower(), str(category or "provenance").strip().lower() or "provenance")


def techniques_from_text(text: str) -> list[str]:
    found = re.findall(r"T\d{4}(?:\.\d{3})?", text or "")
    expanded: list[str] = []
    for item in found:
        if item == "T1543":
            expanded.append("T1543.004")
        else:
            expanded.append(item)
    return sorted(set(expanded))


def mappings_for_rule(rule_id: str, category: str, name: str = "", mitre_mapping: str = "") -> list[FrameworkMapping]:
    normalized = normalize_category(category)
    mappings = list(CATEGORY_BASE_MAPPINGS.get(normalized, CATEGORY_BASE_MAPPINGS["provenance"]))
    rule_text = f"{rule_id} {name}".lower()
    technique_ids = set(techniques_from_text(mitre_mapping))
    if "launchdaemon" in rule_text:
        technique_ids.add("T1543.004")
    if "launchagent" in rule_text:
        technique_ids.add("T1543.001")
    if "login_item" in rule_text or "login item" in rule_text:
        technique_ids.add("T1547.015")
    if "cron" in rule_text or " at" in rule_text:
        technique_ids.add("T1053")
    if "admin" in rule_text:
        technique_ids.update({"T1078", "T1087"})
    if "new_admin" in rule_text or "create account" in rule_text:
        technique_ids.add("T1136")
    if "port" in rule_text or "listener" in rule_text or "nmap" in rule_text:
        technique_ids.add("T1046")
    for technique_id in sorted(technique_ids):
        if technique_id in MITRE_BY_TECHNIQUE:
            technique_name, tactic = MITRE_BY_TECHNIQUE[technique_id]
            candidate = mitre(technique_id, technique_name, tactic, f"Rule {rule_id} references behavior aligned with {technique_name}.", "medium")
            if candidate not in mappings:
                mappings.append(candidate)
    return dedupe_mappings(mappings)


def mappings_for_finding(payload: dict[str, Any]) -> list[FrameworkMapping]:
    existing = payload.get("framework_mappings") or []
    if existing:
        return [mapping_from_dict(item) for item in existing if isinstance(item, dict)]
    mappings = mappings_for_rule(
        str(payload.get("rule_id") or payload.get("trigger_rule_id") or payload.get("id") or ""),
        str(payload.get("category") or ""),
        str(payload.get("title") or ""),
        str(payload.get("mitre_mapping") or payload.get("mitre") or ""),
    )
    cves = [str(item) for item in payload.get("cve_ids", []) if item]
    if not cves and payload.get("cve_id"):
        cves = [str(payload.get("cve_id", ""))]
    for cve_id in cves:
        if cve_id.startswith("CVE-"):
            mappings.append(nvd_cve(cve_id, "Finding references a CVE identifier for vulnerability context."))
            if payload.get("kev") or cve_id in payload.get("kev_cves", []):
                mappings.append(cisa_kev(cve_id, "Finding references a CVE present in CISA KEV metadata."))
    return dedupe_mappings(mappings)


def mapping_from_dict(item: dict[str, Any]) -> FrameworkMapping:
    return FrameworkMapping(
        framework=str(item.get("framework", "")),
        id=str(item.get("id", "")),
        name=str(item.get("name", "")),
        category=str(item.get("category", "")),
        description=str(item.get("description", "")),
        relevance=str(item.get("relevance", "")),
        confidence=str(item.get("confidence", "medium")),
        evidence_required=[str(value) for value in item.get("evidence_required", [])],
        reference_url=str(item.get("reference_url", "")),
    )


def dedupe_mappings(mappings: list[FrameworkMapping]) -> list[FrameworkMapping]:
    seen: set[tuple[str, str]] = set()
    deduped: list[FrameworkMapping] = []
    for mapping in mappings:
        key = (mapping.framework, mapping.id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(mapping)
    return deduped


def mapping_dicts(mappings: list[FrameworkMapping]) -> list[dict[str, Any]]:
    return [mapping.to_dict() for mapping in dedupe_mappings(mappings)]


def extract_mapping_fields(mappings: list[FrameworkMapping]) -> dict[str, list[str]]:
    return {
        "nist_csf_functions": sorted({mapping.category for mapping in mappings if mapping.framework == "NIST_CSF_2_0" and mapping.category in NIST_CSF_FUNCTIONS}),
        "nist_800_53_controls": sorted({mapping.id for mapping in mappings if mapping.framework == "NIST_800_53_REV5"}),
        "nist_800_61_lifecycle_phase": sorted({mapping.id for mapping in mappings if mapping.framework == "NIST_800_61_REV3"}),
        "mitre_attack_techniques": sorted({mapping.id for mapping in mappings if mapping.framework == "MITRE_ATTACK_MACOS"}),
        "cisa_kev_refs": sorted({mapping.id for mapping in mappings if mapping.framework == "CISA_KEV"}),
        "cve_refs": sorted({mapping.id for mapping in mappings if mapping.framework == "NVD_CVE"}),
    }


def framework_summary_for_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    csf = Counter()
    mitre_tactics = Counter()
    controls = Counter()
    techniques = Counter()
    categories = Counter()
    confidences = Counter()
    unmapped: list[dict[str, str]] = []
    for finding in findings:
        mappings = mappings_for_finding(finding)
        if not mappings:
            unmapped.append({"title": str(finding.get("title", "")), "category": str(finding.get("category", ""))})
            continue
        for mapping in mappings:
            categories[mapping.framework] += 1
            confidences[mapping.confidence] += 1
            if mapping.framework == "NIST_CSF_2_0":
                csf[mapping.category] += 1
            elif mapping.framework == "NIST_800_53_REV5":
                controls[f"{mapping.id} {mapping.name}".strip()] += 1
            elif mapping.framework == "MITRE_ATTACK_MACOS":
                mitre_tactics[mapping.category] += 1
                techniques[f"{mapping.id} {mapping.name}".strip()] += 1
    return {
        "nist_csf": dict(sorted(csf.items())),
        "mitre_attack_macos": dict(sorted(mitre_tactics.items())),
        "nist_800_53_controls": dict(controls.most_common(20)),
        "top_mitre_techniques": dict(techniques.most_common(20)),
        "mappings_by_framework": dict(sorted(categories.items())),
        "mapping_confidence": dict(sorted(confidences.items())),
        "unmapped_findings": unmapped,
        "unmapped_count": len(unmapped),
    }


def rule_coverage_summary(rules: dict[str, Any]) -> dict[str, Any]:
    findings = [
        {
            "id": rule.rule_id,
            "rule_id": rule.rule_id,
            "title": rule.name,
            "category": rule.category,
            "framework_mappings": [mapping.to_dict() if hasattr(mapping, "to_dict") else mapping for mapping in getattr(rule, "framework_mappings", [])],
        }
        for rule in rules.values()
    ]
    summary = framework_summary_for_findings(findings)
    summary["total_rules"] = len(rules)
    summary["checks_without_mappings"] = [
        {"rule_id": item["rule_id"], "title": item["title"], "category": item["category"]}
        for item in findings
        if not item.get("framework_mappings")
    ]
    return summary


def validate_mapping_payload(mapping: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    framework = str(mapping.get("framework", ""))
    mapping_id = str(mapping.get("id", ""))
    if framework not in SUPPORTED_FRAMEWORKS:
        problems.append(f"unsupported framework {framework}")
    if framework == "NIST_CSF_2_0" and str(mapping.get("category", "")) not in NIST_CSF_FUNCTIONS:
        problems.append(f"invalid NIST CSF function {mapping.get('category', '')}")
    if framework == "MITRE_ATTACK_MACOS" and not re.match(r"^T\d{4}(?:\.\d{3})?$", mapping_id):
        problems.append(f"invalid MITRE technique id {mapping_id}")
    return problems
