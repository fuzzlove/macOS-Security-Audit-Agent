from __future__ import annotations

import hashlib
from typing import Any

from mac_audit_agent.remediation.cisa_kev_enrichment import generate_kev_priority
from mac_audit_agent.remediation.finding_taxonomy import cve_ids_from_finding, normalize_finding_type, taxonomy_for_finding
from mac_audit_agent.remediation.mitre_mapper import generate_mitre_examination_steps, generate_mitre_mitigation_guidance
from mac_audit_agent.remediation.models import POAMItem, RecommendedFix, SourceMapping
from mac_audit_agent.remediation.nvd_enrichment import enrich_cve, generate_cve_recommended_fix


def _finding_dict(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return dict(finding)
    if hasattr(finding, "to_dict"):
        return dict(finding.to_dict())
    return dict(getattr(finding, "__dict__", {}))


def _source_versions() -> list[dict[str, str]]:
    return [
        {"source_id": "nvd_cve_api", "version": "NVD public CVE API/data feeds when locally cached or available"},
        {"source_id": "cisa_kev_catalog", "version": "CISA KEV public catalog when locally cached or available"},
        {"source_id": "mitre_attack_enterprise_mitigations", "version": "MITRE ATT&CK Enterprise public mitigations"},
        {"source_id": "apple_diagnostics", "version": "Apple public support guidance"},
    ]


def _msaa_mapping(notes: str) -> SourceMapping:
    return SourceMapping(
        source_type="INTERNAL_MSAA_RULE",
        source_id="msaa_local_recommendation",
        source_url="local-msaa://remediation/recommendation-engine",
        source_version="local rule guidance",
        mapping_confidence="supporting_evidence",
        notes=notes,
    )


def build_recommended_fix(finding: Any, evidence_context: dict[str, Any] | None = None, source_registry: dict[str, Any] | None = None) -> RecommendedFix:
    item = _finding_dict(finding)
    evidence_context = evidence_context or {}
    finding_id = str(item.get("id") or item.get("finding_id") or item.get("event_id") or _stable_id(item))
    finding_type = normalize_finding_type(item)
    taxonomy = taxonomy_for_finding(item)
    severity = str(item.get("severity", "info")).lower()
    confidence = str(item.get("confidence", "medium") or "medium")
    cves = cve_ids_from_finding(item)
    mappings: list[SourceMapping] = [_msaa_mapping("MSAA generated local recommendation because every finding requires actionable next steps.")]
    limitations: list[str] = [
        "Recommendations are decision support, not a compliance certification or endorsement by Apple, CISA, NIST, DoD, NSA, MITRE, PCI SSC, or NVD."
    ]
    nvd_context: dict[str, Any] | None = None
    kev_context: dict[str, Any] | None = None
    mitre_context = generate_mitre_mitigation_guidance(item)
    if mitre_context.get("source_mappings"):
        mappings.extend(SourceMapping(**mapping) for mapping in mitre_context["source_mappings"])
        limitations.extend(mitre_context.get("limitations", []))

    immediate_action = item.get("recommended_next_steps") or item.get("remediation_suggestion") or taxonomy.remediation_actions[0]
    recommended_fix = item.get("remediation_suggestion") or taxonomy.remediation_actions[-1]
    validation_steps = list(item.get("verification_steps") or item.get("recommended_verification_steps") or taxonomy.examination_steps)
    further_steps = list(taxonomy.examination_steps) + generate_mitre_examination_steps(item)
    evidence_to_collect = list(taxonomy.evidence_checklist)
    false_positive_checks = list(item.get("false_positive_hints") or []) + list(taxonomy.false_positive_checks)
    apple_context = _apple_context_for_finding(item, taxonomy.apple_evidence_needs)
    nist_context = _nist_context_for_finding(finding_type)
    dod_cmmc_context = _cmmc_context_for_finding(finding_type)

    if cves:
        nvd_records = [enrich_cve(cve_id) for cve_id in cves]
        cve_fixes = [generate_cve_recommended_fix(record, item) for record in nvd_records]
        nvd_context = {"cves": nvd_records, "generated_fixes": cve_fixes}
        first_fix = cve_fixes[0] if cve_fixes else {}
        recommended_fix = first_fix.get("recommended_fix", recommended_fix)
        validation_steps = list(first_fix.get("validation_steps", validation_steps))
        for cve_id in cves:
            mappings.append(
                SourceMapping(
                    source_type="NVD",
                    source_id=cve_id,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    source_version="NVD CVE detail",
                    mapping_confidence="direct",
                    notes="CVE enrichment must be validated against the installed local product/version.",
                )
            )
        if any(not record.get("available") for record in nvd_records):
            limitations.append("NVD enrichment unavailable for one or more CVEs; use vendor advisory and local evidence.")
    if cves or item.get("kev"):
        kev_input = dict(item)
        kev_input["cve_ids"] = cves
        kev_context = generate_kev_priority(kev_input)
        if kev_context.get("known_exploited"):
            immediate_action = "Urgently review and remediate this known-exploited vulnerability according to vendor/CISA KEV guidance."
            mappings.append(
                SourceMapping(
                    source_type="CISA_KEV",
                    source_id=";".join(match.get("cve_id", "") for match in kev_context.get("matches", [])),
                    source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    source_version="CISA KEV catalog",
                    mapping_confidence="direct",
                    notes="KEV indicates known exploitation of the vulnerability, not confirmed local compromise.",
                )
            )
            evidence_to_collect.extend(["CISA KEV action/due date", "remediation or exception record"])

    if finding_type in {"emerging_ttp_no_cve", "suspected_malware_or_threat_activity", "unknown_unsigned_behavior"} and not cves:
        immediate_action = "Preserve evidence and perform analyst review before assigning a malware family, CVE, actor, or zero-day label."
        recommended_fix = "Contain confirmed unwanted behavior using approved local incident-response procedures; do not delete evidence before review."
        limitations.append("No CVE, malware family, threat actor, or zero-day label is assigned because authoritative evidence is not present.")

    poam = POAMItem(
        weakness=str(item.get("title") or finding_type.replace("_", " ")),
        affected_asset=str(item.get("related_path") or item.get("affected_asset") or item.get("detected_product") or "This Mac"),
        recommended_fix=str(recommended_fix),
        source_standard=", ".join(sorted({mapping.source_type for mapping in mappings})),
        validation_method="; ".join(validation_steps[:3]),
        evidence_required=evidence_to_collect[:8],
        residual_risk="Residual risk remains until validation evidence confirms the finding is remediated, mitigated, accepted, or false positive.",
    )
    return RecommendedFix(
        fix_id=f"fix-{finding_id}",
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        confidence=confidence,
        summary=f"Recommended action for {item.get('title') or finding_type.replace('_', ' ')}.",
        immediate_action=str(immediate_action),
        recommended_fix=str(recommended_fix),
        further_examination_steps=_dedupe(further_steps),
        false_positive_checks=_dedupe(false_positive_checks),
        evidence_to_collect=_dedupe(evidence_to_collect),
        validation_steps=_dedupe(validation_steps),
        rollback_or_safety_notes=[
            str(item.get("what_can_go_wrong") or "Preserve evidence and confirm business impact before making changes."),
            "Prefer reversible mitigation first when ownership or impact is uncertain.",
        ],
        user_skill_level=taxonomy.skill_level,  # type: ignore[arg-type]
        source_mappings=mappings,
        cve_context=nvd_context,
        cisa_kev_context=kev_context,
        mitre_context=mitre_context if mitre_context.get("techniques") else None,
        apple_context=apple_context,
        dod_cmmc_context=dod_cmmc_context,
        nist_context=nist_context,
        source_versions=_source_versions(),
        limitations=_dedupe(limitations),
        possible_new_threat=finding_type in {"emerging_ttp_no_cve", "suspected_malware_or_threat_activity"},
        actor_attribution_status="insufficient_evidence" if finding_type in {"emerging_ttp_no_cve", "suspected_malware_or_threat_activity"} else "none",
        suggested_submission_targets=_submission_targets(finding_type),
        required_evidence_before_attribution=["timeline", "process tree", "file hashes", "network endpoints", "trusted source correlation"] if finding_type in {"emerging_ttp_no_cve", "suspected_malware_or_threat_activity"} else [],
        false_positive_status="not_reviewed",
        analyst_notes="Suppression must be explicit, reversible, and must not delete evidence.",
        supporting_evidence=[str(item.get("evidence_summary") or item.get("evidence") or "")],
        poam=poam,
    )


def enrich_finding_with_recommendation(finding: dict[str, Any]) -> dict[str, Any]:
    item = dict(finding)
    if isinstance(item.get("recommended_fix"), dict):
        return item
    fix = build_recommended_fix(item)
    payload = fix.to_dict()
    item["recommended_fix"] = payload
    item["remediation_sources"] = payload.get("source_mappings", [])
    item["apple_diagnostics_export_options"] = _apple_export_options()
    item["false_positive_review"] = {
        "status": payload.get("false_positive_status", "not_reviewed"),
        "checks": payload.get("false_positive_checks", []),
        "analyst_notes": payload.get("analyst_notes", ""),
        "suppression_requires_explicit_action": True,
    }
    item["poam"] = payload.get("poam")
    if not item.get("recommended_next_steps"):
        item["recommended_next_steps"] = payload["immediate_action"]
    if not item.get("remediation_suggestion"):
        item["remediation_suggestion"] = payload["recommended_fix"]
    if not item.get("verification_steps"):
        item["verification_steps"] = payload["validation_steps"]
    if not item.get("false_positive_notes"):
        item["false_positive_notes"] = "; ".join(payload["false_positive_checks"][:3])
    return item


def ensure_recommended_fixes(findings: list[Any]) -> list[dict[str, Any]]:
    return [enrich_finding_with_recommendation(_finding_dict(finding)) for finding in findings]


def _apple_context_for_finding(finding: dict[str, Any], needs: list[str]) -> dict[str, Any]:
    return {
        "evidence_export_recommended": bool(needs) or "apple" in " ".join(str(v) for v in finding.values()).lower(),
        "evidence_needs": needs or ["MSAA finding JSON", "macOS version/build", "user-reviewed report excerpt"],
        "privacy_warning": "Apple diagnostic packages may contain sensitive system information. Review the package before sharing.",
        "auto_submit": False,
    }


def _nist_context_for_finding(finding_type: str) -> dict[str, Any]:
    return {
        "mapped_to": ["NIST CSF 2.0 Detect", "NIST SP 800-53 Rev. 5 AU/SI/CM as applicable"],
        "claim": "Mapped for readiness context only; no compliance or certification claim.",
        "manual_review_required": finding_type in {"unknown", "emerging_ttp_no_cve", "suspected_malware_or_threat_activity"},
    }


def _cmmc_context_for_finding(finding_type: str) -> dict[str, Any]:
    return {
        "mapped_to": ["CMMC Access Control", "Audit and Accountability", "Configuration Management", "Incident Response"],
        "claim": "POA&M-ready context only; no CMMC certification claim.",
        "manual_review_required": True,
    }


def _submission_targets(finding_type: str) -> list[str]:
    targets = ["internal SOC/IR team", "vendor support"]
    if finding_type.startswith("apple") or finding_type in {"apple_security_update_gap", "apple_diagnostic_hardware_issue"}:
        targets.extend(["Apple Feedback Assistant", "Apple Support"])
    if finding_type in {"suspected_malware_or_threat_activity", "emerging_ttp_no_cve"}:
        targets.extend(["Apple Feedback Assistant", "Apple Security reporting if a vulnerability/security issue is suspected"])
    return _dedupe(targets)


def _apple_export_options() -> list[str]:
    return [
        "General Apple Support Evidence",
        "Apple Feedback Assistant Evidence",
        "Apple Security / Vulnerability Evidence",
        "Network / Wireless Diagnostics Evidence",
        "Crash / App Hang Evidence",
        "Hardware / Apple Diagnostics Evidence Checklist",
        "False Positive Review Package",
        "Custom Evidence Package",
    ]


def _stable_id(item: dict[str, Any]) -> str:
    digest = hashlib.sha256(repr(sorted(item.items())).encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"finding-{digest}"


def _dedupe(values: list[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
