"""Operator-facing explanation of MSAA framework coverage boundaries.

This catalog is intentionally capability oriented. Framework mappings explain
relevance; they do not by themselves establish implementation or compliance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FrameworkScope:
    framework: str
    coverage_role: str
    automated_evidence: str
    remaining_responsibility: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityCoverage:
    capability: str
    security_question: str
    status: str
    evidence: str
    framework_relevance: str
    limitations: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageSheetEntry:
    """Plain-language companion to one technical capability claim."""

    capability: str
    plain_language_goal: str
    what_msaa_checks: str
    coverage_label: str
    evidence_user_sees: str
    recommended_next_step: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


FRAMEWORK_SCOPES = (
    FrameworkScope(
        "NIST CSF 2.0",
        "Endpoint evidence supporting selected Govern, Identify, Protect, Detect, Respond, and Recover outcomes.",
        "Local configuration, inventory, detection, response, recovery-readiness, and sensor-health observations.",
        "The organization must define scope, Current/Target Profiles, risk decisions, owners, policies, suppliers, and outcome effectiveness.",
    ),
    FrameworkScope(
        "NIST SP 800-53 Rev. 5",
        "Technical evidence mapped to selected controls; this is not a complete control-baseline assessment.",
        "Repeatable endpoint observations relevant to AC, AU, CA, CM, IA, IR, SC, and SI control families where mapped.",
        "Selection, tailoring, organization-defined parameters, common controls, implementation statements, interviews, and SP 800-53A assessment remain external.",
    ),
    FrameworkScope(
        "MITRE ATT&CK Enterprise — macOS",
        "Threat-informed detection context with detector-and-test-qualified coverage claims.",
        "Technique-linked detections, process/path evidence, timelines, persistence changes, network context, and validation references.",
        "A mapped technique is not automatically detected. Procedure variants, telemetry gaps, evasion, prevention, and response exercise results must be reviewed.",
    ),
    FrameworkScope(
        "CMMC / NIST SP 800-171",
        "Readiness evidence for selected endpoint-relevant requirements.",
        "Mapped check results, evidence status, missing-evidence indicators, and suggested remediation support.",
        "Contract scope, CUI boundary, SSP, policies, people/process evidence, assessment method, affirmations, SPRS, C3PAO, and DIBCAC conclusions remain external.",
    ),
    FrameworkScope(
        "NIST SP 800-61 Rev. 3",
        "Incident-response lifecycle context for preparation, detection, analysis, containment, recovery, and lessons learned.",
        "Alerts, investigation timelines, analyst notes, evidence references, containment records, and recovery status where available.",
        "The incident-response plan, authority, communications, legal decisions, exercises, coordination, and organization-wide lessons-learned process remain external.",
    ),
    FrameworkScope(
        "CISA KEV and NVD/CVE",
        "Vulnerability and exploitation-priority reference data, not compliance frameworks.",
        "CVE identifiers, KEV correlation, affected-product context, definition provenance, and remediation references when available.",
        "Asset applicability, vendor validation, compensating controls, patch authorization, and remediation acceptance require analyst or owner review.",
    ),
)


CAPABILITY_COVERAGE = (
    CapabilityCoverage(
        "Apple security posture",
        "Are core macOS security controls configured as expected?",
        "EVIDENCE-BACKED",
        "Observed and expected state for encryption, firewall, Gatekeeper, updates, sharing, authentication, privacy, recovery, and logging checks.",
        "NIST CSF Identify/Protect/Detect; NIST SP 800-53 AC, CM, IA, SC, and SI families.",
        "Availability varies by macOS version, permissions, MDM ownership, and supported APIs; organization policy still defines the expected state.",
    ),
    CapabilityCoverage(
        "Software integrity and applications",
        "What software exists, who signed it, and what changed?",
        "EVIDENCE-BACKED",
        "Application inventory, signature/Gatekeeper state, hashes, quarantine state, first/last seen context, and install/removal observations.",
        "NIST CSF Identify/Protect; NIST SP 800-53 CM-8 and SI-7; ATT&CK execution/defense-evasion context.",
        "Unsigned software is not automatically malicious; publisher intent, approved software lists, and business authorization require review.",
    ),
    CapabilityCoverage(
        "Persistence Intelligence",
        "What mechanisms can restart or preserve execution?",
        "EVIDENCE-BACKED",
        "LaunchAgents, LaunchDaemons, login items, scheduled tasks, startup files, helpers, profiles, ownership, signing, executable target, and baseline drift.",
        "NIST CSF Detect/Respond; NIST SP 800-53 AU-6, CM-3, CM-6, SI-4; ATT&CK T1543, T1547, and T1053 context.",
        "Some background-item attribution and protected locations depend on Full Disk Access, OS APIs, and available native telemetry.",
    ),
    CapabilityCoverage(
        "Identity and privileged access",
        "Who can access or administer the Mac, and did privilege change?",
        "PARTIAL",
        "Local users, administrators, login state, remote-access exposure, account changes, privilege observations, and access-risk findings.",
        "NIST CSF Protect/Detect; NIST SP 800-53 AC-2, AC-6, IA, and AU-6; ATT&CK valid-account context.",
        "Cloud identity, IdP conditional access, HR authorization, service-account ownership, and complete authentication attribution require external sources.",
    ),
    CapabilityCoverage(
        "Network and DNS visibility",
        "Which services and connections exist, and are resolver settings drifting?",
        "PARTIAL",
        "Listeners, active/recent connections, process association where available, resolver/search-domain/hosts changes, VPN/proxy context, and boundary test evidence.",
        "NIST CSF Identify/Detect/Protect; NIST SP 800-53 SC-7 and SI-4; ATT&CK discovery and command-and-control context.",
        "Packet content is not required or broadly captured; process attribution, ASN/reputation enrichment, and enterprise boundary intent may be unavailable offline.",
    ),
    CapabilityCoverage(
        "Ransomware and malware defenses",
        "Is current activity consistent with malware or destructive file behavior?",
        "PARTIAL",
        "YARA and hash matches, definition provenance, file-change signals, entropy/rename/delete behavior, backup targeting, process ancestry, and containment records.",
        "NIST CSF Protect/Detect/Respond/Recover; NIST SP 800-53 SI-3/SI-4/SI-7; ATT&CK T1486 and T1490 context.",
        "Coverage depends on current validated definitions and sensor access. Statistical or unsigned-file signals alone do not prove malware or ransomware.",
    ),
    CapabilityCoverage(
        "Behavioral Telemetry",
        "How does current security activity differ from the workstation profile and baseline?",
        "PARTIAL",
        "Coverage-aware process, network, DNS, authentication, privilege, persistence, and security-setting aggregates with reason codes and baseline versions.",
        "NIST CSF Detect/Respond; NIST SP 800-53 CA-7, SI-4, AU-6; ATT&CK enrichment across observed behaviors.",
        "Cold-start, missing sensors, research/developer workflows, and legitimate changes reduce confidence; unusual behavior is not proof of malicious intent.",
    ),
    CapabilityCoverage(
        "Host IDS and exploitation evidence",
        "Do correlated events resemble malicious execution or suspected exploitation?",
        "PARTIAL",
        "Process, crash, memory-indicator, filesystem, network, code-signing, YARA, and post-crash sequence evidence with severity and confidence kept separate.",
        "NIST CSF Detect/Respond; NIST SP 800-53 SI-4 and IR; ATT&CK execution, exploitation, and interpreter context.",
        "macOS telemetry restrictions can limit memory and ancestry evidence. Suspected RCE and behavioral similarity are not confirmation of exploitation.",
    ),
    CapabilityCoverage(
        "Sensor health and reliability",
        "Is MSAA collecting enough trustworthy telemetry to support its conclusions?",
        "EVIDENCE-BACKED",
        "Sensor state, coverage, heartbeat, freshness, latency, drops, queue pressure, recovery attempts, diagnostic exports, and historical availability.",
        "NIST CSF Govern/Detect; NIST SP 800-53 CA-7 and SI-4.",
        "A healthy sensor establishes operational availability, not that every event was observed; platform permission and source blind spots remain documented.",
    ),
    CapabilityCoverage(
        "Investigation and evidence",
        "What happened, what supports the finding, and what should the analyst do next?",
        "EVIDENCE-BACKED",
        "Common alerts, investigation priority, timelines, Flight Recorder references, analyst disposition, notes, evidence completeness, and exportable reports.",
        "NIST CSF Respond/Recover; NIST SP 800-53 AU and IR families; NIST SP 800-61 lifecycle support.",
        "MSAA does not replace legal review, enterprise case management, forensic imaging, chain-of-custody policy, or qualified incident responders.",
    ),
    CapabilityCoverage(
        "Privacy and permission review",
        "Which applications hold sensitive macOS permissions?",
        "PARTIAL",
        "Camera, microphone, screen recording, accessibility, location, contacts, photos, Full Disk Access, automation, and risk-context review where observable.",
        "NIST CSF Govern/Identify/Protect and selected NIST SP 800-53 privacy/access-control context.",
        "Legitimate authorization cannot be inferred from permission state alone; user purpose, organizational policy, consent, and MDM records require review.",
    ),
    CapabilityCoverage(
        "Governance, policy, workforce, and suppliers",
        "Are organization-wide administrative and management requirements operating effectively?",
        "EXTERNAL / MANUAL",
        "MSAA can attach endpoint observations and evidence references but does not claim automated organizational governance evidence.",
        "Relevant across NIST CSF Govern, NIST SP 800-53, CMMC, and NIST SP 800-61.",
        "Policies, interviews, training effectiveness, contracts, legal obligations, supplier assurance, risk acceptance, and assessor conclusions remain client responsibilities.",
    ),
)


COVERAGE_SHEET = (
    CoverageSheetEntry(
        "Apple security posture",
        "Checks whether important built-in macOS protections are turned on and configured as expected.",
        "Encryption, firewall, Gatekeeper, software updates, sharing, authentication, privacy, recovery, and security logging.",
        "Strong local evidence",
        "Observed state, expected state, result, reason, and the evidence used for each supported check.",
        "Review failed or unknown checks, confirm the expected state matches your policy, then remediate one approved change at a time.",
    ),
    CoverageSheetEntry(
        "Software integrity and applications",
        "Shows what software is installed, who signed it, and which applications recently changed.",
        "Application inventory, signing and Gatekeeper state, hashes, quarantine state, and installation or removal history.",
        "Strong local evidence",
        "Software identity, publisher, path, hash, signing result, and change context where macOS exposes it.",
        "Investigate risky combinations such as an unknown publisher, persistence, and unusual network activity; unsigned alone is not malware.",
    ),
    CoverageSheetEntry(
        "Persistence Intelligence",
        "Finds software configured to start again at login, boot, or on a schedule.",
        "LaunchAgents, LaunchDaemons, login and background items, scheduled tasks, shell startup files, helpers, and profiles.",
        "Strong local evidence",
        "Location, owner, permissions, executable target, signature, baseline change, and safe remediation context.",
        "Verify the owning application and business need before backing up and quarantining an unexpected persistence item.",
    ),
    CoverageSheetEntry(
        "Identity and privileged access",
        "Highlights who can sign in, administer the Mac, or reach it remotely.",
        "Local users, administrators, login state, remote-access exposure, account changes, and observed privilege activity.",
        "Useful but limited",
        "Endpoint account and privilege observations plus access-risk findings.",
        "Compare findings with your identity provider, HR authorization, service-account ownership, and approved administrator list.",
    ),
    CoverageSheetEntry(
        "Network and DNS visibility",
        "Explains which services listen for connections, where applications connect, and whether DNS settings changed.",
        "Listeners, connections, process links where available, resolvers, search domains, hosts file, VPN, proxy, and boundary-test results.",
        "Useful but limited",
        "Connection and configuration evidence with attribution and enrichment when sensors and offline data permit.",
        "Confirm expected enterprise boundaries and VPN/DHCP behavior; use an authorized packet capture only when more evidence is needed.",
    ),
    CoverageSheetEntry(
        "Ransomware and malware defenses",
        "Looks for known malicious files and behavior resembling destructive or ransomware activity.",
        "Validated YARA and hash matches, file-change patterns, entropy, renames, deletion, backup targeting, and suspicious process context.",
        "Useful but limited",
        "Definition provenance, matching evidence, contributing behavior signals, confidence, and containment history.",
        "Keep definitions healthy and investigate correlated signals; do not treat a statistical or unsigned-file signal as proof by itself.",
    ),
    CoverageSheetEntry(
        "Behavioral Telemetry",
        "Learns normal security-relevant activity for this workstation profile and identifies meaningful deviations.",
        "Process, network, DNS, authentication, privilege, persistence, and security-setting activity using time-aware local baselines.",
        "Useful but limited",
        "Observed versus expected activity, baseline confidence, coverage state, reason codes, and related evidence.",
        "Allow the baseline to mature, resolve missing sensors, and investigate unusual behavior without assuming malicious intent.",
    ),
    CoverageSheetEntry(
        "Host IDS and exploitation evidence",
        "Correlates events that may indicate malicious execution, memory corruption, or suspected exploitation.",
        "Processes, crashes, memory indicators, files, network activity, signing, YARA, and post-crash execution sequences.",
        "Useful but limited",
        "Severity and confidence, exact reason codes, timeline, process relationships, sensor coverage, and evidence completeness.",
        "Validate suspected activity with the preserved timeline and diagnostics; suspected RCE is not confirmed exploitation.",
    ),
    CoverageSheetEntry(
        "Sensor health and reliability",
        "Shows whether MSAA has enough working telemetry to support its findings.",
        "Sensor state, heartbeat, freshness, latency, drops, queues, recovery attempts, diagnostics, and historical availability.",
        "Strong local evidence",
        "Current health, affected coverage, recovery outcome, and operational history.",
        "Repair degraded sensors and rerun affected checks; healthy sensors improve confidence but cannot guarantee every event was observed.",
    ),
    CoverageSheetEntry(
        "Investigation and evidence",
        "Organizes what happened, why it matters, and which evidence supports the conclusion.",
        "Alerts, investigation priority, timelines, Flight Recorder references, analyst notes, dispositions, and evidence exports.",
        "Strong local evidence",
        "A linked investigation record with recommendations, evidence completeness, audit history, and exportable artifacts.",
        "Preserve original evidence, document the analyst decision, and use qualified responders for legal, forensic, or enterprise escalation.",
    ),
    CoverageSheetEntry(
        "Privacy and permission review",
        "Shows which applications may access sensitive macOS capabilities.",
        "Camera, microphone, screen recording, accessibility, location, contacts, photos, Full Disk Access, and automation where observable.",
        "Useful but limited",
        "Application, permission, observed state, and neutral risk context.",
        "Confirm the user purpose, consent, policy, and MDM record before changing a legitimate application's permission.",
    ),
    CoverageSheetEntry(
        "Governance, policy, workforce, and suppliers",
        "Makes clear which organization-wide requirements cannot be proven by inspecting one Mac.",
        "MSAA can attach endpoint observations, but it does not automate policies, interviews, training, contracts, or assessor decisions.",
        "Needs external review",
        "Referenced endpoint evidence that a consultant can include in a broader assessment.",
        "Collect policies, people and process evidence, supplier records, scope decisions, risk acceptance, and qualified assessor conclusions separately.",
    ),
)


_COVERAGE_LABEL_BY_STATUS = {
    "EVIDENCE-BACKED": "Strong local evidence",
    "PARTIAL": "Useful but limited",
    "EXTERNAL / MANUAL": "Needs external review",
}


def framework_coverage_catalog() -> dict[str, Any]:
    statuses: dict[str, int] = {}
    for item in CAPABILITY_COVERAGE:
        statuses[item.status] = statuses.get(item.status, 0) + 1
    return {
        "qualification": "Framework mappings are evidence indexes, not certification or compliance conclusions.",
        "summary": {
            "frameworks_explained": len(FRAMEWORK_SCOPES),
            "capabilities_explained": len(CAPABILITY_COVERAGE),
            "coverage_sheet_entries": len(COVERAGE_SHEET),
            "status_counts": statuses,
        },
        "coverage_sheet_guide": {
            "purpose": "Start here for a plain-language view of what MSAA checks, what evidence it produces, and what still requires a person or another system.",
            "status_labels": dict(_COVERAGE_LABEL_BY_STATUS),
            "reading_order": [
                "Choose the security question you care about.",
                "Read what MSAA checks and the evidence you will receive.",
                "Review the coverage boundary before relying on the result.",
                "Use the technical tabs for exact framework and detector mappings.",
            ],
        },
        "coverage_sheet": [item.to_dict() for item in COVERAGE_SHEET],
        "frameworks": [item.to_dict() for item in FRAMEWORK_SCOPES],
        "capabilities": [item.to_dict() for item in CAPABILITY_COVERAGE],
    }


__all__ = [
    "CAPABILITY_COVERAGE",
    "COVERAGE_SHEET",
    "FRAMEWORK_SCOPES",
    "CapabilityCoverage",
    "CoverageSheetEntry",
    "FrameworkScope",
    "framework_coverage_catalog",
]
