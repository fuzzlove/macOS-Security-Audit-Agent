from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from mac_audit_agent.frameworks.source_registry import official_framework_sources


CMMC_DISCLAIMER = (
    "MSAA provides CMMC/NIST readiness mapping and evidence support. This output is not a CMMC certification, "
    "C3PAO assessment, DoD authorization, NIST compliance attestation, or legal determination."
)

IMPLEMENTATION_STATUSES = {"met", "not_met", "partially_met", "not_applicable", "inherited", "not_tested", "evidence_missing", "unknown"}
EVIDENCE_STATUSES = {"collected", "missing", "insufficient", "manual_review_required", "not_applicable"}


@dataclass
class CMMCRequirement:
    cmmc_id: str
    level: int
    domain: str
    practice_id: str
    title: str
    requirement_text: str
    assessment_objectives: list[str]
    discussion: str
    source_id: str
    source_version: str
    mapped_nist_controls: list[str]
    evidence_expectations: list[str]
    assessment_method: str = "unknown"
    applies_to: str = "unknown"
    implementation_status: str = "not_tested"
    msaa_check_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CMMCDomain:
    domain_id: str
    name: str
    description: str
    level_coverage: dict[int, int]
    requirement_count: int
    mapped_msaa_check_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CMMCEvidenceItem:
    evidence_id: str
    requirement_id: str
    source_check_id: str
    artifact_type: str
    artifact_path: str
    collected_at: str
    command_or_collector: str
    result_summary: str
    evidence_status: str
    analyst_note: str = ""
    recommended_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CMMCReadinessResult:
    result_id: str
    created_at: str
    target_level: int
    scope_name: str
    source_versions: list[dict[str, Any]]
    total_requirements: int
    mapped_requirements: int
    met_count: int
    not_met_count: int
    partial_count: int
    not_tested_count: int
    evidence_missing_count: int
    not_applicable_count: int
    readiness_score: int
    requirements: list[dict[str, Any]]
    domain_summaries: list[dict[str, Any]]
    top_gaps: list[dict[str, Any]]
    evidence_items: list[dict[str, Any]]
    limitations: list[str]
    disclaimer: str = CMMC_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmmc_requirements() -> list[CMMCRequirement]:
    # Compact, source-referenced readiness set for MSAA's local endpoint evidence. Policy/process-only items remain manual.
    return [
        _req("CMMC-L1-AC-1", 1, "AC", "Access Control", "AC.L1-3.1.1", "Limit system access to authorized users.", ["Examine local user/admin inventory.", "Interview owner for authorization basis."], ["AC-2", "AC-3"], ["local users", "admin users", "guest/disabled account state"], ["scan.admin_persistence"], "examine", "FCI"),
        _req("CMMC-L1-IA-1", 1, "IA", "Identification and Authentication", "IA.L1-3.5.1", "Identify system users and processes acting on behalf of users.", ["Examine account inventory.", "Review authentication posture where observable."], ["IA-2"], ["local users", "login posture"], ["settings.enforcement"], "examine", "FCI"),
        _req("CMMC-L1-SI-1", 1, "SI", "System and Information Integrity", "SI.L1-3.14.1", "Identify, report, and correct information and system flaws in a timely manner.", ["Examine update/vulnerability evidence.", "Review Apple Exposure and integrity findings."], ["SI-2"], ["Apple Exposure Assessment", "integrity check", "CVE/KEV review"], ["scan.apple_exposure", "scan.visibility_integrity"], "examine", "FCI"),
        _req("CMMC-L2-AU-1", 2, "AU", "Audit and Accountability", "AU.L2-3.3.1", "Create and retain system audit logs and records.", ["Examine monitor events and alert traces.", "Review report/evidence exports."], ["AU-2", "AU-6"], ["monitor events", "alert delivery trace", "report artifacts"], ["alert.delivery_trace", "exports.evidence_package"], "examine", "CUI"),
        _req("CMMC-L2-CM-1", 2, "CM", "Configuration Management", "CM.L2-3.4.1", "Establish and maintain baseline configurations.", ["Examine baseline drift evidence.", "Review LaunchAgent/Daemon and sharing setting changes."], ["CM-2", "CM-3", "CM-6"], ["baseline drift", "launchd inventory", "sharing settings"], ["scan.baseline_drift", "persistence.workflow"], "examine", "CUI"),
        _req("CMMC-L2-IR-1", 2, "IR", "Incident Response", "IR.L2-3.6.1", "Establish an operational incident-handling capability.", ["Examine incident response evidence artifacts.", "Manual review of IR plan and roles required."], ["IR-4", "IR-6"], ["live response collection", "security timeline", "evidence snapshots", "incident response plan"], ["alert.bottom_right_rendering", "exports.evidence_package"], "examine", "CUI", ["manual evidence required: incident response plan and roles"]),
        _req("CMMC-L2-MP-1", 2, "MP", "Media Protection", "MP.L2-3.8.7", "Control the use of removable media on system components.", ["Examine USB/external storage observations.", "Manual review of media policy required."], ["MP-7"], ["USB devices", "external storage", "Bluetooth/HID context", "media policy"], ["scan.physical_devices"], "examine", "CUI", ["manual evidence required: media handling policy"]),
        _req("CMMC-L2-RA-1", 2, "RA", "Risk Assessment", "RA.L2-3.11.2", "Scan for vulnerabilities and remediate findings.", ["Examine Apple Exposure, CVE/KEV, and risk scoring evidence.", "Manual review of risk acceptance required."], ["RA-5"], ["Apple Exposure Assessment", "CVE/KEV correlation", "risk scoring"], ["scan.apple_exposure", "core.assessment_builder"], "examine", "CUI"),
        _req("CMMC-L2-SC-1", 2, "SC", "System and Communications Protection", "SC.L2-3.13.1", "Monitor and control communications at system boundaries.", ["Examine listeners, DNS/gateway/VPN/proxy, and firewall posture where collected."], ["SC-7"], ["Network Intelligence", "listener detection", "DNS/gateway/VPN/proxy review"], ["network_intelligence.collectors", "network_intelligence.reports"], "examine", "CUI"),
        _req("CMMC-L2-SI-2", 2, "SI", "System and Information Integrity", "SI.L2-3.14.6", "Monitor systems to detect attacks and indicators of potential attacks.", ["Examine monitoring coverage, persistence detection, suspicious paths/processes, and alert evidence."], ["SI-4", "SI-7"], ["monitoring coverage", "persistence intelligence", "alert pipeline", "integrity manifest"], ["daemon.heartbeat", "persistence.workflow", "alert.bottom_right_rendering"], "examine", "CUI"),
        _req("CMMC-L3-SI-1", 3, "SI", "System and Information Integrity", "SI.L3-3.14.x", "Support enhanced integrity and threat monitoring readiness.", ["Examine advanced integrity and persistence evidence.", "Manual review of enhanced CUI protections required."], ["NIST SP 800-172 SI enhanced requirements"], ["strict integrity verification", "persistence intelligence", "manual enhanced control evidence"], ["scan.visibility_integrity", "persistence.workflow"], "examine", "CUI_high_value", ["manual evidence required for NIST SP 800-172 enhanced practices"]),
    ]


def _req(
    cmmc_id: str,
    level: int,
    domain_id: str,
    domain: str,
    practice_id: str,
    text: str,
    objectives: list[str],
    nist: list[str],
    expectations: list[str],
    checks: list[str],
    method: str,
    applies_to: str,
    limitations: list[str] | None = None,
) -> CMMCRequirement:
    source_id = "cmmc_32_cfr_170" if level == 1 else "cmmc_level_2_assessment_guide" if level == 2 else "cmmc_level_3_assessment_guide"
    source_version = "32 CFR Part 170 current" if level == 1 else "Current official DoD CMMC guide reference"
    return CMMCRequirement(
        cmmc_id=cmmc_id,
        level=level,
        domain=domain,
        practice_id=practice_id,
        title=f"{domain} readiness support",
        requirement_text=text,
        assessment_objectives=objectives,
        discussion="MSAA provides local macOS technical evidence and identifies manual evidence needed for analyst review.",
        source_id=source_id,
        source_version=source_version,
        mapped_nist_controls=nist,
        evidence_expectations=expectations,
        assessment_method=method,
        applies_to=applies_to,
        msaa_check_ids=checks,
        limitations=limitations or [],
    )


def source_versions() -> list[dict[str, Any]]:
    return [
        {
            "source_id": source.source_id,
            "framework": source.framework,
            "title": source.title,
            "version": source.version,
            "retrieved_at": source.retrieved_at,
            "source_url": source.source_url,
            "normative": source.normative,
        }
        for source in official_framework_sources()
    ]


def build_cmmc_readiness(
    *,
    target_level: int = 2,
    scope_name: str = "This Mac only",
    completed_check_ids: set[str] | None = None,
    evidence_root: str = "",
) -> CMMCReadinessResult:
    completed = completed_check_ids or set()
    requirements = [item for item in cmmc_requirements() if item.level <= target_level]
    evidence_items: list[CMMCEvidenceItem] = []
    for requirement in requirements:
        matching = [check_id for check_id in requirement.msaa_check_ids if check_id in completed]
        if matching and requirement.limitations:
            requirement.implementation_status = "partially_met"
        elif matching:
            requirement.implementation_status = "met"
        elif requirement.msaa_check_ids:
            requirement.implementation_status = "evidence_missing"
        else:
            requirement.implementation_status = "not_tested"
        for check_id in requirement.msaa_check_ids:
            collected = check_id in completed
            status = "collected" if collected else "missing"
            if collected and requirement.limitations:
                status = "manual_review_required"
            evidence_items.append(
                CMMCEvidenceItem(
                    evidence_id=f"evidence-{uuid4().hex[:10]}",
                    requirement_id=requirement.cmmc_id,
                    source_check_id=check_id,
                    artifact_type="pre_uat_check",
                    artifact_path=evidence_root,
                    collected_at=utc_now_iso() if collected else "",
                    command_or_collector=check_id,
                    result_summary="MSAA technical evidence collected for analyst review." if collected else "MSAA evidence not collected in the current run.",
                    evidence_status=status,
                    analyst_note="; ".join(requirement.limitations),
                    recommended_fix="Collect manual organizational evidence." if requirement.limitations else "Run the related MSAA check.",
                )
            )
    status_counts = {status: sum(1 for item in requirements if item.implementation_status == status) for status in IMPLEMENTATION_STATUSES}
    score = round((status_counts["met"] + status_counts["partially_met"] * 0.5) / max(1, len(requirements)) * 100)
    domain_summaries = _domain_summaries(requirements, evidence_items)
    top_gaps = [item.to_dict() for item in requirements if item.implementation_status in {"evidence_missing", "not_tested", "partially_met"}][:10]
    limitations = [
        "MSAA cannot determine contractual CMMC scope by itself. Scope must be confirmed by the organization, contract requirements, and authorized personnel.",
        "Human/process/policy requirements require manual evidence and are not automatically satisfied by local technical scans.",
    ]
    return CMMCReadinessResult(
        result_id=f"cmmc-readiness-{uuid4().hex[:12]}",
        created_at=utc_now_iso(),
        target_level=target_level,
        scope_name=scope_name,
        source_versions=source_versions(),
        total_requirements=len(requirements),
        mapped_requirements=sum(1 for item in requirements if item.msaa_check_ids),
        met_count=status_counts["met"],
        not_met_count=status_counts["not_met"],
        partial_count=status_counts["partially_met"],
        not_tested_count=status_counts["not_tested"],
        evidence_missing_count=status_counts["evidence_missing"],
        not_applicable_count=status_counts["not_applicable"],
        readiness_score=score,
        requirements=[item.to_dict() for item in requirements],
        domain_summaries=domain_summaries,
        top_gaps=top_gaps,
        evidence_items=[item.to_dict() for item in evidence_items],
        limitations=limitations,
    )


def _domain_summaries(requirements: list[CMMCRequirement], evidence_items: list[CMMCEvidenceItem]) -> list[dict[str, Any]]:
    domains = sorted({item.domain for item in requirements})
    summaries = []
    for domain in domains:
        domain_requirements = [item for item in requirements if item.domain == domain]
        evidence = [item for item in evidence_items if item.requirement_id in {req.cmmc_id for req in domain_requirements}]
        summaries.append(
            {
                "domain": domain,
                "requirements": len(domain_requirements),
                "mapped": sum(1 for item in domain_requirements if item.msaa_check_ids),
                "evidence_collected": sum(1 for item in evidence if item.evidence_status == "collected"),
                "missing_evidence": sum(1 for item in evidence if item.evidence_status == "missing"),
                "manual_review_required": sum(1 for item in evidence if item.evidence_status == "manual_review_required"),
                "status": "ready" if all(item.implementation_status == "met" for item in domain_requirements) else "review_required",
            }
        )
    return summaries


__all__ = [
    "CMMC_DISCLAIMER",
    "CMMCRequirement",
    "CMMCDomain",
    "CMMCEvidenceItem",
    "CMMCReadinessResult",
    "cmmc_requirements",
    "build_cmmc_readiness",
]
