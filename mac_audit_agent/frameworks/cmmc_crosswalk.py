from __future__ import annotations

from typing import Any

from mac_audit_agent.frameworks.cmmc import cmmc_requirements


CHECK_AREA_MAP = {
    "settings.enforcement": ("CMMC-L1-IA-1", "supporting_evidence"),
    "scan.admin_persistence": ("CMMC-L1-AC-1", "partial"),
    "scan.apple_exposure": ("CMMC-L1-SI-1", "supporting_evidence"),
    "scan.visibility_integrity": ("CMMC-L1-SI-1", "supporting_evidence"),
    "alert.delivery_trace": ("CMMC-L2-AU-1", "direct"),
    "exports.evidence_package": ("CMMC-L2-AU-1", "supporting_evidence"),
    "integrity.signing": ("CMMC-L2-SI-2", "supporting_evidence"),
    "scan.baseline_drift": ("CMMC-L2-CM-1", "supporting_evidence"),
    "persistence.workflow": ("CMMC-L2-CM-1", "supporting_evidence"),
    "alert.bottom_right_rendering": ("CMMC-L2-IR-1", "supporting_evidence"),
    "scan.physical_devices": ("CMMC-L2-MP-1", "supporting_evidence"),
    "core.assessment_builder": ("CMMC-L2-RA-1", "supporting_evidence"),
    "network_intelligence.collectors": ("CMMC-L2-SC-1", "supporting_evidence"),
    "network_intelligence.reports": ("CMMC-L2-SC-1", "supporting_evidence"),
    "daemon.heartbeat": ("CMMC-L2-SI-2", "supporting_evidence"),
}

CATEGORY_MAP = {
    "identity": "CMMC-L1-AC-1",
    "accounts": "CMMC-L1-AC-1",
    "persistence": "CMMC-L2-CM-1",
    "network": "CMMC-L2-SC-1",
    "hardware": "CMMC-L2-MP-1",
    "physical": "CMMC-L2-MP-1",
    "integrity": "CMMC-L2-SI-2",
    "vulnerability": "CMMC-L2-RA-1",
    "monitor": "CMMC-L2-SI-2",
}


def map_msaa_check_to_cmmc(check_id: str) -> list[dict[str, Any]]:
    requirements = {item.cmmc_id: item for item in cmmc_requirements()}
    if check_id not in CHECK_AREA_MAP:
        return []
    requirement_id, confidence = CHECK_AREA_MAP[check_id]
    requirement = requirements[requirement_id]
    return [_mapping(requirement, check_id, confidence)]


def map_msaa_finding_to_cmmc(finding: dict[str, Any]) -> list[dict[str, Any]]:
    category = str(finding.get("category", "")).lower()
    text = " ".join(str(finding.get(key, "")) for key in ["title", "description", "evidence"]).lower()
    requirement_ids = {req_id for key, req_id in CATEGORY_MAP.items() if key in category or key in text}
    requirements = {item.cmmc_id: item for item in cmmc_requirements()}
    return [_mapping(requirements[req_id], str(finding.get("id") or finding.get("finding_id") or ""), "partial") for req_id in sorted(requirement_ids)]


def map_cmmc_to_nist(requirement_id: str) -> list[str]:
    for requirement in cmmc_requirements():
        if requirement.cmmc_id == requirement_id:
            return requirement.mapped_nist_controls
    return []


def map_cmmc_to_evidence(requirement_id: str) -> list[str]:
    for requirement in cmmc_requirements():
        if requirement.cmmc_id == requirement_id:
            return requirement.evidence_expectations
    return []


def cmmc_mappings_for_msaa_check(check_id: str) -> list[dict[str, Any]]:
    return map_msaa_check_to_cmmc(check_id)


def cmmc_mappings_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    return map_msaa_finding_to_cmmc(finding)


def _mapping(requirement, source_check_id: str, confidence: str) -> dict[str, Any]:
    return {
        "framework": f"CMMC_LEVEL_{requirement.level}",
        "requirement_id": requirement.cmmc_id,
        "practice_id": requirement.practice_id,
        "domain": requirement.domain,
        "title": requirement.title,
        "related_nist_controls": requirement.mapped_nist_controls,
        "source_check_id": source_check_id,
        "mapping_confidence": confidence,
        "manual_evidence_required": bool(requirement.limitations),
        "source_id": requirement.source_id,
        "source_version": requirement.source_version,
        "limitations": requirement.limitations,
    }


__all__ = [
    "map_msaa_check_to_cmmc",
    "map_msaa_finding_to_cmmc",
    "map_cmmc_to_nist",
    "map_cmmc_to_evidence",
    "cmmc_mappings_for_msaa_check",
    "cmmc_mappings_for_finding",
]
