from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

from mac_audit_agent.assessment import SecurityAssessment
from mac_audit_agent.apple_exposure_guidance import build_apple_exposure_update_guide
from mac_audit_agent.exporters.remediation import get_suggested_fix
from mac_audit_agent.frameworks.cmmc import build_cmmc_readiness
from mac_audit_agent.frameworks.cmmc_crosswalk import map_msaa_finding_to_cmmc
from mac_audit_agent.frameworks.poam import poam_from_cmmc_readiness
from mac_audit_agent.remediation.recommendation_engine import enrich_finding_with_recommendation


SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class ExportOptions:
    include_executive_summary: bool = True
    include_detailed_findings: bool = True
    include_evidence_appendix: bool = False
    include_framework_mappings: bool = True
    include_remediation_plan: bool = True
    include_historical_events: bool = False
    include_raw_technical_appendix: bool = False
    include_limitations: bool = True
    redact_usernames_hostnames: bool = False


@dataclass
class ExportAssessmentData:
    metadata: dict[str, Any]
    summary: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    remediation_items: list[dict[str, Any]] = field(default_factory=list)
    apple_exposure: list[dict[str, Any]] = field(default_factory=list)
    network_activity: list[dict[str, Any]] = field(default_factory=list)
    admin_persistence: list[dict[str, Any]] = field(default_factory=list)
    physical_devices: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    framework_mappings: list[dict[str, Any]] = field(default_factory=list)
    cmmc_summary: dict[str, Any] = field(default_factory=dict)
    cmmc_requirements: list[dict[str, Any]] = field(default_factory=list)
    cmmc_evidence_matrix: list[dict[str, Any]] = field(default_factory=list)
    cmmc_poam: list[dict[str, Any]] = field(default_factory=list)
    cmmc_source_versions: list[dict[str, Any]] = field(default_factory=list)
    cmmc_manual_evidence: list[dict[str, Any]] = field(default_factory=list)
    visibility_integrity: list[dict[str, Any]] = field(default_factory=list)
    application_integrity: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        items = value.get("items") or value.get("recent_events") or value.get("events") or []
        return items if isinstance(items, list) else []
    return []


def _finding_id(item: dict[str, Any], index: int) -> str:
    return str(item.get("id") or item.get("finding_id") or item.get("event_id") or f"F-{index:03d}")


def _category(item: dict[str, Any]) -> str:
    return str(item.get("category") or item.get("event_type") or "General")


def _title(item: dict[str, Any]) -> str:
    return str(item.get("title") or item.get("name") or item.get("event_type") or "Security finding")


def _description(item: dict[str, Any]) -> str:
    return str(item.get("description") or item.get("summary") or item.get("evidence_summary") or item.get("evidence") or "")


def _mappings(item: dict[str, Any]) -> list[dict[str, Any]]:
    mappings = item.get("framework_mappings") or []
    return mappings if isinstance(mappings, list) else []


def _join(values: Any) -> str:
    if isinstance(values, list):
        return ", ".join(str(value) for value in values if value)
    if isinstance(values, dict):
        return ", ".join(f"{key}: {value}" for key, value in values.items())
    return str(values or "")


def _normalize_finding(item: dict[str, Any], index: int) -> dict[str, Any]:
    finding = enrich_finding_with_recommendation(dict(item))
    finding_id = _finding_id(finding, index)
    advice = get_suggested_fix(finding).to_dict()
    mappings = _mappings(finding)
    recommended_fix = finding.get("recommended_fix", {}) if isinstance(finding.get("recommended_fix"), dict) else {}
    poam = recommended_fix.get("poam") if isinstance(recommended_fix, dict) else {}
    finding.update(
        {
            "finding_id": finding_id,
            "severity": str(finding.get("severity", "info")).lower(),
            "confidence": str(finding.get("confidence", "")),
            "category": _category(finding),
            "title": _title(finding),
            "description": _description(finding),
            "evidence_summary": str(finding.get("evidence_summary") or finding.get("evidence") or ""),
            "impact": str(finding.get("impact") or finding.get("why_this_matters") or "Review required to determine operational impact."),
            "suggested_fix": str(finding.get("suggested_fix") or finding.get("recommended_next_steps") or advice["suggested_fix"]),
            "recommended_fix_summary": str(recommended_fix.get("summary", "")),
            "immediate_action": str(recommended_fix.get("immediate_action", "")),
            "recommended_fix_detail": str(recommended_fix.get("recommended_fix", "")),
            "examine_further": _join(recommended_fix.get("further_examination_steps", [])),
            "evidence_to_collect": _join(recommended_fix.get("evidence_to_collect", [])),
            "false_positive_review": _join(recommended_fix.get("false_positive_checks", [])),
            "source_mappings_text": _join(
                [
                    f"{mapping.get('source_type', '')}:{mapping.get('source_id', '')} ({mapping.get('mapping_confidence', '')})"
                    for mapping in recommended_fix.get("source_mappings", [])
                    if isinstance(mapping, dict)
                ]
            ),
            "apple_evidence_checklist": _join((recommended_fix.get("apple_context") or {}).get("evidence_needs", [])),
            "validation_step": str(finding.get("validation_step") or advice["validation_step"]),
            "false_positive_notes": str(finding.get("false_positive_notes") or "Confirm ownership, expected behavior, and business need before closing as a false positive."),
            "difficulty": advice["difficulty"],
            "expected_impact": advice["expected_impact"],
            "rollback_note": advice["rollback_note"],
            "status": str(finding.get("status") or "Open"),
            "nist_csf": _join(finding.get("nist_csf_functions")),
            "nist_800_53": _join(finding.get("nist_800_53_controls")),
            "mitre_attack": _join(finding.get("mitre_attack_techniques")),
            "cve": _join(finding.get("cve_ids") or finding.get("cve_refs")),
            "cisa_kev": _join(finding.get("cisa_kev_refs") or finding.get("kev_status")),
            "framework_mappings": mappings,
            "poam_weakness": str((poam or {}).get("weakness", "")),
            "poam_affected_asset": str((poam or {}).get("affected_asset", "")),
            "poam_recommended_fix": str((poam or {}).get("recommended_fix", "")),
            "poam_validation_method": str((poam or {}).get("validation_method", "")),
        }
    )
    return finding


def _summary_items(summary: dict[str, Any], category: str) -> list[dict[str, Any]]:
    rows = []
    for item in _safe_list(summary):
        if isinstance(item, dict):
            rows.append({**item, "category": item.get("category", category)})
    if not rows and summary:
        rows.append({"category": category, "summary": summary.get("summary", ""), "status": summary.get("status", "")})
    return rows


def _framework_rows(findings: list[dict[str, Any]], assessment: SecurityAssessment) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        for mapping in finding.get("framework_mappings", []) or []:
            if isinstance(mapping, dict):
                rows.append(
                    {
                        "finding_id": finding["finding_id"],
                        "framework": mapping.get("framework", ""),
                        "control_id": mapping.get("id", ""),
                        "name": mapping.get("name", ""),
                        "category": mapping.get("category", ""),
                        "mapping_confidence": mapping.get("confidence", ""),
                        "notes": mapping.get("relevance", ""),
                    }
                )
    for framework, values in (assessment.framework_summary or {}).items():
        if isinstance(values, dict):
            for key, value in values.items():
                rows.append({"finding_id": "", "framework": framework, "control_id": key, "name": "", "category": "", "mapping_confidence": "", "notes": str(value)})
    return rows


def _completed_check_ids(assessment: SecurityAssessment, findings: list[dict[str, Any]]) -> set[str]:
    completed: set[str] = set()
    diagnostics = assessment.diagnostics if isinstance(assessment.diagnostics, dict) else {}
    for key, value in diagnostics.items():
        if isinstance(value, dict) and str(value.get("status", "")).lower() in {"pass", "passed", "ready", "ok", "verified", "collected"}:
            completed.add(str(key))
        elif value:
            completed.add(str(key))
    if assessment.apple_exposure_summary:
        completed.add("scan.apple_exposure")
    if assessment.network_activity_summary:
        completed.add("network_intelligence.collectors")
        completed.add("network_intelligence.reports")
    if assessment.admin_persistence_summary:
        completed.add("persistence.workflow")
    if assessment.physical_device_summary:
        completed.add("scan.physical_devices")
    if assessment.monitor_integrity_summary:
        completed.add("scan.visibility_integrity")
        completed.add("daemon.heartbeat")
    for finding in findings:
        for key in ("source_check_id", "check_id", "audit_check_id"):
            if finding.get(key):
                completed.add(str(finding[key]))
    return completed


def _build_cmmc_export_payload(assessment: SecurityAssessment, findings: list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(getattr(assessment, "cmmc_readiness", None), dict) and assessment.cmmc_readiness:
        payload = dict(assessment.cmmc_readiness)
    else:
        readiness = build_cmmc_readiness(
            target_level=2,
            scope_name=str((assessment.diagnostics or {}).get("cmmc_scope", "This Mac only")) if isinstance(assessment.diagnostics, dict) else "This Mac only",
            completed_check_ids=_completed_check_ids(assessment, findings),
        )
        payload = readiness.to_dict()
    requirements = payload.get("requirements", [])
    evidence_matrix: list[dict[str, Any]] = []
    for item in payload.get("evidence_items", []):
        if not isinstance(item, dict):
            continue
        requirement = next((req for req in requirements if req.get("cmmc_id") == item.get("requirement_id")), {})
        evidence_matrix.append(
            {
                "cmmc_level": requirement.get("level", ""),
                "cmmc_requirement_id": item.get("requirement_id", ""),
                "domain": requirement.get("domain", ""),
                "requirement_summary": requirement.get("requirement_text", ""),
                "related_nist_control": ", ".join(str(value) for value in requirement.get("mapped_nist_controls", [])),
                "msaa_check": item.get("source_check_id", ""),
                "evidence_collected": item.get("result_summary", ""),
                "evidence_location": item.get("artifact_path", ""),
                "evidence_status": item.get("evidence_status", ""),
                "manual_evidence_needed": item.get("analyst_note", ""),
                "suggested_fix": item.get("recommended_fix", ""),
                "analyst_notes": item.get("analyst_note", ""),
            }
        )
    for finding in findings:
        for mapping in map_msaa_finding_to_cmmc(finding):
            evidence_matrix.append(
                {
                    "cmmc_level": mapping.get("level", ""),
                    "cmmc_requirement_id": mapping.get("requirement_id", ""),
                    "domain": mapping.get("domain", ""),
                    "requirement_summary": mapping.get("practice_id", ""),
                    "related_nist_control": ", ".join(str(value) for value in mapping.get("related_nist_controls", [])),
                    "msaa_check": mapping.get("source_check_id", finding.get("finding_id", "")),
                    "evidence_collected": finding.get("evidence_summary", ""),
                    "evidence_location": "",
                    "evidence_status": "manual_review_required" if mapping.get("manual_evidence_required") else "partial",
                    "manual_evidence_needed": "; ".join(str(value) for value in mapping.get("limitations", [])),
                    "suggested_fix": finding.get("suggested_fix", ""),
                    "analyst_notes": mapping.get("mapping_confidence", ""),
                }
            )
    manual_evidence = [
        {
            "requirement_id": item.get("cmmc_id", ""),
            "evidence_needed": "; ".join(str(value) for value in item.get("limitations", [])) or "Analyst confirmation required.",
            "suggested_document_name": f"{item.get('domain', 'CMMC')} evidence record",
            "owner": "",
            "status": "manual_review_required",
            "notes": item.get("discussion", ""),
        }
        for item in payload.get("top_gaps", [])
        if isinstance(item, dict) and item.get("limitations")
    ]
    poam = [item.to_dict() for item in poam_from_cmmc_readiness(payload)]
    return {
        "summary": payload,
        "requirements": requirements,
        "evidence_matrix": evidence_matrix,
        "poam": poam,
        "source_versions": payload.get("source_versions", []),
        "manual_evidence": manual_evidence,
    }


def _apple_exposure_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _summary_items(summary, "Apple Exposure")
    cards = summary.get("display_cards") or summary.get("cards") or summary.get("alerts") or summary.get("items") or []
    if isinstance(cards, list) and cards:
        rows = [item for item in cards if isinstance(item, dict)]
    enriched: list[dict[str, Any]] = []
    for row in rows:
        guide = build_apple_exposure_update_guide(row, summary.get("inventory", {}) if isinstance(summary.get("inventory", {}), dict) else {}, summary)
        enriched.append(
            {
                **row,
                "advisory": row.get("advisory", row.get("title", row.get("summary", ""))),
                "severity": row.get("severity", row.get("forecast_level", summary.get("level", ""))),
                "affected_component": row.get("affected_component", row.get("affected_local_product", row.get("component", ""))),
                "current_version": row.get("current_version", row.get("detected_version", "")),
                "recommended_action": row.get("recommended_action", row.get("what_to_do", "; ".join(guide.recommended_actions))),
                "database_checked": row.get("database_checked", summary.get("generated_at", summary.get("timestamp", ""))),
                "last_successful_update": row.get("last_successful_update", summary.get("last_successful_update_time", "")),
                "freshness_status": row.get("freshness_status", summary.get("cache_age_text", summary.get("cache_age", ""))),
                "update_guidance_title": guide.title,
                "update_guidance_summary": "; ".join(guide.recommended_actions),
                "verification_steps": "; ".join(guide.verification_steps),
                "evidence_preservation_notes": "; ".join(guide.evidence_preservation_notes or guide.pre_update_precautions),
                "official_references": "; ".join(guide.official_references),
                "limitations": "; ".join(guide.limitations),
            }
        )
    return enriched


def _application_integrity_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    integrity = summary.get("application_integrity") or summary.get("integrity_verification") or summary.get("monitor_protection_integrity") or summary
    if not isinstance(integrity, dict) or not integrity:
        return []
    rows = [
        {
            "scope": integrity.get("source_type", integrity.get("scope", "application")),
            "status": integrity.get("overall_status", integrity.get("status", "unknown")),
            "manifest_path": integrity.get("manifest_path", ""),
            "checked_at": integrity.get("checked_at", integrity.get("last_checked", "")),
            "manifest_source_type": integrity.get("source_type", ""),
            "current_install_mode": integrity.get("current_install_mode", ""),
            "manifest_app_version": integrity.get("manifest_app_version", ""),
            "current_app_version": integrity.get("current_app_version", ""),
            "manifest_build_id": integrity.get("manifest_build_id", ""),
            "current_build_id": integrity.get("current_build_id", ""),
            "manifest_git_commit": integrity.get("manifest_git_commit", ""),
            "current_git_commit": integrity.get("current_git_commit", ""),
            "manifest_package_version": integrity.get("manifest_package_version", ""),
            "current_package_version": integrity.get("current_package_version", ""),
            "manifest_root_path": integrity.get("manifest_root_path", ""),
            "current_root_path": integrity.get("current_root_path", ""),
            "manifest_created_at": integrity.get("manifest_created_at", ""),
            "manifest_hash": integrity.get("manifest_hash", ""),
            "verification_result_id": integrity.get("verification_result_id", integrity.get("result_id", "")),
            "verified_at": integrity.get("verified_at", integrity.get("checked_at", integrity.get("last_checked", ""))),
            "cached_result": integrity.get("cached_result", ""),
            "cache_valid": integrity.get("cache_valid", ""),
            "cache_invalidated_reason": integrity.get("cache_invalidated_reason", ""),
            "ignored_manifests": "; ".join(str(item.get("path", "")) for item in integrity.get("ignored_manifests", []) if isinstance(item, dict)),
            "exact_mismatch_reason": integrity.get("exact_mismatch_reason", ""),
            "matched_count": integrity.get("matched_count", ""),
            "mismatched_count": integrity.get("mismatched_count", ""),
            "missing_count": integrity.get("missing_count", ""),
            "extra_count": integrity.get("extra_count", ""),
            "recommended_action": "; ".join(str(item) for item in integrity.get("recommended_actions", [])) or integrity.get("recommendation", ""),
        }
    ]
    for item in integrity.get("file_results", []):
        if isinstance(item, dict) and item.get("verification_status") in {"mismatch", "missing", "extra", "unknown"}:
            rows.append(
                {
                    "scope": "file",
                    "status": item.get("verification_status", ""),
                    "manifest_path": integrity.get("manifest_path", ""),
                    "checked_at": integrity.get("checked_at", integrity.get("last_checked", "")),
                    "relative_path": item.get("relative_path", ""),
                    "mismatch_reasons": ", ".join(str(reason) for reason in item.get("mismatch_reasons", [])),
                    "exact_mismatch_reason": item.get("error", "") or ", ".join(str(reason) for reason in item.get("mismatch_reasons", [])),
                    "recommended_action": "Review this file against the trusted MSAA source or package.",
                }
            )
    for mismatch in integrity.get("mismatch_details", []):
        if isinstance(mismatch, dict):
            rows.append(
                {
                    "scope": "metadata",
                    "status": integrity.get("overall_status", integrity.get("status", "unknown")),
                    "manifest_path": integrity.get("manifest_path", ""),
                    "checked_at": integrity.get("checked_at", integrity.get("last_checked", "")),
                    "relative_path": mismatch.get("field", ""),
                    "mismatch_reasons": mismatch.get("message", ""),
                    "exact_mismatch_reason": mismatch.get("message", ""),
                    "recommended_action": "Resolve the integrity manifest mismatch using the safe trusted-build workflow.",
                }
            )
    return rows


def build_export_assessment_data(assessment: SecurityAssessment, options: ExportOptions | None = None) -> ExportAssessmentData:
    options = options or ExportOptions()
    all_findings = [
        *assessment.critical_findings,
        *assessment.high_findings,
        *assessment.medium_findings,
        *assessment.info_findings,
    ]
    findings = [_normalize_finding(item, index) for index, item in enumerate(all_findings, start=1)]
    counts = {severity: sum(1 for item in findings if item.get("severity") == severity) for severity in SEVERITIES}
    hostname = "Redacted Host" if options.redact_usernames_hostnames else assessment.hostname
    metadata = {
        "report_title": "MSAA Security Assessment",
        "hostname": hostname or socket.gethostname(),
        "macos_version": assessment.macos_version,
        "app_version": assessment.app_version,
        "assessment_date": assessment.created_at,
        "assessment_id": assessment.assessment_id,
        "generated_by": "macOS Security Audit Agent",
        "confidentiality_notice": "Confidential security assessment. Share only with authorized reviewers.",
    }
    summary = {
        "assessment_status": assessment.assessment_status,
        "overall_score": assessment.overall_score,
        "risk_level": assessment.risk_level,
        "executive_summary": assessment.executive_summary if options.include_executive_summary else "",
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
        "monitor_status": assessment.monitor_integrity_summary.get("status", "unavailable"),
        "apple_exposure_status": assessment.apple_exposure_summary.get("status", assessment.apple_exposure_summary.get("level", "unavailable")),
        "database_checked_date": assessment.apple_exposure_summary.get("database_checked", assessment.apple_exposure_summary.get("generated_at", "")),
    }
    remediation_items = []
    for finding in findings if options.include_remediation_plan else []:
        priority = "Immediate" if finding["severity"] in {"critical", "high"} else ("Short-Term" if finding["severity"] == "medium" else "Routine")
        remediation_items.append(
            {
                "priority": priority,
                "severity": finding["severity"],
                "finding_id": finding["finding_id"],
                "recommended_fix": finding["suggested_fix"],
                "difficulty": finding["difficulty"],
                "expected_impact": finding["expected_impact"],
                "validation_step": finding["validation_step"],
                "owner": "",
                "status": finding["status"],
                "due_date": "",
                "notes": finding["rollback_note"],
            }
        )
    timeline = []
    for finding in findings if options.include_historical_events else []:
        if finding.get("timestamp"):
            timeline.append(
                {
                    "timestamp": finding.get("timestamp", ""),
                    "severity": finding["severity"],
                    "event_type": finding.get("event_type", ""),
                    "source": finding.get("source", ""),
                    "summary": finding["evidence_summary"] or finding["description"],
                    "related_finding": finding["finding_id"],
                    "evidence": finding["evidence_summary"],
                    "suggested_fix": finding["suggested_fix"],
                }
            )
    cmmc_payload = _build_cmmc_export_payload(assessment, findings)
    return ExportAssessmentData(
        metadata=metadata,
        summary=summary,
        findings=findings if options.include_detailed_findings else [],
        remediation_items=remediation_items,
        apple_exposure=_apple_exposure_rows(assessment.apple_exposure_summary),
        network_activity=_summary_items(assessment.network_activity_summary, "Network Activity"),
        admin_persistence=_summary_items(assessment.admin_persistence_summary, "Admin Persistence"),
        physical_devices=_summary_items(assessment.physical_device_summary, "Physical Devices"),
        timeline=timeline,
        framework_mappings=_framework_rows(findings, assessment) if options.include_framework_mappings else [],
        cmmc_summary=cmmc_payload["summary"],
        cmmc_requirements=cmmc_payload["requirements"],
        cmmc_evidence_matrix=cmmc_payload["evidence_matrix"],
        cmmc_poam=cmmc_payload["poam"],
        cmmc_source_versions=cmmc_payload["source_versions"],
        cmmc_manual_evidence=cmmc_payload["manual_evidence"],
        visibility_integrity=_summary_items(assessment.monitor_integrity_summary, "Visibility Integrity"),
        application_integrity=_application_integrity_rows(assessment.monitor_integrity_summary),
        limitations=list(assessment.limitations) if options.include_limitations else [],
    )
