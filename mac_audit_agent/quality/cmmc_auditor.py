from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.assessment import SecurityAssessment, export_security_assessment_html, export_security_assessment_json
from mac_audit_agent.runtime.optional_dependencies import OptionalDependencyError
from mac_audit_agent.frameworks.cmmc import CMMC_DISCLAIMER, build_cmmc_readiness, cmmc_requirements
from mac_audit_agent.frameworks.cmmc_crosswalk import map_msaa_check_to_cmmc
from mac_audit_agent.frameworks.poam import poam_from_cmmc_readiness
from mac_audit_agent.frameworks.source_registry import official_framework_sources
from mac_audit_agent.frameworks.standards_profiles import validate_catalog, validate_profile_isolation
from mac_audit_agent.frameworks.report_conformance import ConformanceStatus, evaluate_report
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


FORBIDDEN_WORDING = [
    "CMMC certified",
    "NIST compliant",
    "government approved",
    "guarantees certification",
    "passes CMMC assessment",
    "official assessment result",
    "NSA approved",
    "DoD approved",
    "CISA certified",
    "PCI certified",
    "guarantees compliance",
    "passes official assessment",
    "copied from macos_security",
    "based on stolen code",
]


def run_cmmc_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks = [
        _comparative_review_generated_check(),
        _ip_safety_review_generated_check(),
        _no_plagiarism_guardrails_check(),
        _derived_idea_matrix_valid_check(),
        _official_source_registry_check(),
        _source_registry_check(),
        _mapping_integrity_check(),
        _readiness_payload_check(),
        _standards_no_false_claims_check(),
        _no_false_claims_check(),
        _accepted_ideas_have_mappings_check(),
        _manual_evidence_check(),
        _contractual_profile_separated_check(),
        _catalog_completeness_check(),
        _no_invented_score_check(),
        _scope_workflow_gate_check(),
        _assessment_methods_gate_check(),
        _report_conformance_gate_check(),
        _incident_no_submission_check(),
        _roadmap_complete_check(),
        _nsa_acknowledgement_check(),
        _support_author_final_tab_check(),
    ]
    checks.extend(_reports_payload_checks(context))
    return checks


def _comparative_review_generated_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.comparative_review_generated", "Framework Readiness", "macos_security comparative review", "Comparative review documentation exists and handles missing adjacent source safely.", "high", "framework")
    required = [
        Path("docs/MACOS_SECURITY_COMPARATIVE_REVIEW.md"),
        Path("docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md"),
        Path("docs/MSAA_VS_MACOS_SECURITY_COMPARE_CONTRAST.md"),
        Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md"),
        Path("docs/MACOS_SECURITY_DERIVED_IMPLEMENTATION_PLAN.md"),
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        return check.failed("Comparative review documentation is missing.", "Generate the comparative review, IP safety review, idea matrix, and implementation plan.", {"missing": missing})
    review_text = Path("docs/MACOS_SECURITY_COMPARATIVE_REVIEW.md").read_text(encoding="utf-8", errors="replace")
    if "../macos_security" not in review_text or "not found" not in review_text.lower():
        return check.failed("Comparative review does not clearly document adjacent source availability.", "Record whether ../macos_security was found or gracefully unavailable.", {})
    return check.passed("Comparative review documents generated with missing-source-safe handling.", {"documents": [str(path) for path in required]})


def _ip_safety_review_generated_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.ip_safety_review_generated", "Framework Readiness", "IP safety review", "License/IP safety review exists and documents non-copying constraints.", "blocker", "framework")
    path = Path("docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md")
    if not path.exists():
        return check.failed("IP safety review is missing.", "Create docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md before adopting comparative ideas.", {})
    text = path.read_text(encoding="utf-8", errors="replace")
    required = ["Not allowed", "Copied code", "Copied assets", "Copied report templates", "Direct function, class, or module cloning"]
    missing = [item for item in required if item not in text]
    if missing:
        return check.failed("IP safety review is incomplete.", "Document disallowed copying categories and implementation guardrails.", {"missing": missing})
    return check.passed("IP safety review documents non-copying boundaries.", {"path": str(path)})


def _no_plagiarism_guardrails_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.no_plagiarism_guardrails", "Framework Readiness", "non-copying guardrails", "Comparative review includes no-copying and IP safety guardrails.", "blocker", "framework")
    safety = Path("docs/MACOS_SECURITY_IP_SAFETY_REVIEW.md")
    matrix = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md")
    text = (safety.read_text(encoding="utf-8", errors="replace") if safety.exists() else "") + "\n" + (matrix.read_text(encoding="utf-8", errors="replace") if matrix.exists() else "")
    required = ["Copied code", "Copied assets", "standards", "plagiarism_guardrail_notes"]
    missing = [item for item in required if item.lower() not in text.lower()]
    if missing:
        return check.failed("Non-copying guardrails are incomplete.", "Document disallowed copying and per-idea do-not-copy notes.", {"missing": missing})
    return check.passed("IP safety and non-copying guardrails are documented.", {"reviewed_documents": [str(safety), str(matrix)]})


def _derived_idea_matrix_valid_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.derived_idea_matrix_valid", "Framework Readiness", "standards-derived idea matrix", "Accepted ideas include standards mapping, confidence, and guardrail notes.", "high", "framework")
    path = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md")
    if not path.exists():
        return check.failed("Standards-derived improvement matrix is missing.", "Create docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md.", {})
    text = path.read_text(encoding="utf-8", errors="replace")
    required_columns = [
        "idea_id",
        "source_observation_summary",
        "original_MSAA_derivative_feature",
        "official_source_ids",
        "mapping_confidence",
        "plagiarism_guardrail_notes",
        "accepted_for_implementation",
    ]
    missing = [column for column in required_columns if column not in text]
    if missing:
        return check.failed("Standards-derived matrix is missing required fields.", "Update the matrix to the current comparative-review schema.", {"missing": missing})
    if "accepted_for_implementation: yes" not in text.lower() and "| yes |" not in text.lower():
        return check.failed("No accepted derivative improvements are identified.", "Accept only low-copy-risk, standards-backed MSAA-native improvements.", {})
    return check.passed("Standards-derived idea matrix is valid.", {"path": str(path)})


def _official_source_registry_check() -> FunctionalCheck:
    return _source_registry_check_for_id("standards.official_source_registry")


def _source_registry_check() -> FunctionalCheck:
    return _source_registry_check_for_id("frameworks.cmmc_source_registry")


def _source_registry_check_for_id(check_id: str) -> FunctionalCheck:
    check = FunctionalCheck(check_id, "Framework Readiness", "official source registry", "Official framework source registry exists and loads.", "blocker", "framework")
    sources = official_framework_sources()
    cmmc = [item for item in sources if item.framework == "CMMC"]
    nist = [item for item in sources if item.framework == "NIST"]
    required_frameworks = {"CMMC", "NIST", "CISA", "NSA", "PCI", "DFARS", "MITRE"}
    missing = []
    if not any(item.source_id == "cmmc_32_cfr_170" for item in sources):
        missing.append("32 CFR Part 170")
    if not any(item.source_id == "nist_sp_800_171_r3" for item in sources):
        missing.append("NIST SP 800-171 Rev. 3")
    missing_frameworks = sorted(required_frameworks - {item.framework for item in sources})
    allowed_source_types = {
        "government_standard",
        "government_guidance",
        "government_reference",
        "industry_standard",
        "vendor_support_reference",
        "vendor_security_reporting_reference",
        "public_reference",
        "internal_msaa_rule",
    }
    invalid = [
        item.source_id
        for item in sources
        if not item.retrieved_at
        or not item.version
        or not item.source_url.startswith("https://")
        or item.source_type not in allowed_source_types
        or not item.issuing_authority
        or not item.title
    ]
    if missing or invalid:
        return check.failed("Official framework source registry is incomplete.", "Add official/public source metadata with version, retrieved_at, and source_type.", {"missing": missing, "missing_frameworks": missing_frameworks, "invalid": invalid})
    if missing_frameworks:
        return check.failed("Required source framework families are missing.", "Add NIST, CISA, DoD/CMMC, NSA, PCI, DFARS, and MITRE source entries.", {"missing_frameworks": missing_frameworks})
    return check.passed("Official/public framework source registry loaded.", {"cmmc_sources": len(cmmc), "nist_sources": len(nist), "frameworks": sorted({item.framework for item in sources}), "total_sources": len(sources)})


def _mapping_integrity_check() -> FunctionalCheck:
    check = FunctionalCheck("frameworks.cmmc_mapping_integrity", "Framework Readiness", "CMMC mapping integrity", "CMMC mappings have valid source references and confidence.", "blocker", "framework")
    requirements = cmmc_requirements()
    source_ids = {item.source_id for item in official_framework_sources()}
    bad = [item.cmmc_id for item in requirements if item.source_id not in source_ids or not item.source_version]
    mapped = [mapping for check_id in ["scan.physical_devices", "alert.delivery_trace", "network_intelligence.collectors"] for mapping in map_msaa_check_to_cmmc(check_id)]
    missing_confidence = [item for item in mapped if item.get("mapping_confidence") not in {"direct", "partial", "supporting_evidence", "manual_review_required", "not_applicable"}]
    if bad or missing_confidence:
        return check.failed("CMMC mapping source or confidence validation failed.", "Fix source_id/source_version and mapping confidence fields.", {"bad_requirements": bad, "missing_confidence": missing_confidence})
    return check.passed("CMMC mappings have source references and confidence.", {"requirements": len(requirements), "sample_mappings": mapped})


def _readiness_payload_check() -> FunctionalCheck:
    check = FunctionalCheck("frameworks.cmmc_readiness_dashboard", "Framework Readiness", "CMMC readiness payload", "CMMC readiness dashboard/report payload builds.", "high", "framework")
    readiness = build_cmmc_readiness(target_level=2, completed_check_ids={"scan.physical_devices", "alert.delivery_trace", "network_intelligence.collectors"})
    payload = readiness.to_dict()
    if not payload.get("domain_summaries") or not payload.get("source_versions"):
        return check.failed("CMMC readiness payload missing domain summaries or source versions.", "Build CMMC readiness with source versions and domain summaries.", payload)
    return check.passed("CMMC readiness payload built.", {"requirements": payload["total_requirements"], "score": payload["readiness_score"], "domains": len(payload["domain_summaries"])})


def _reports_payload_checks(context: AuditContext) -> list[FunctionalCheck]:
    check = FunctionalCheck("frameworks.cmmc_reports", "Framework Readiness", "CMMC report payloads", "HTML/Excel/Word/JSON report payloads include CMMC sections.", "high", "framework")
    readiness = build_cmmc_readiness(target_level=2, completed_check_ids={"scan.physical_devices", "alert.delivery_trace"})
    poam = poam_from_cmmc_readiness(readiness.to_dict())
    payload = {"cmmc_summary": readiness.to_dict(), "evidence_matrix": readiness.evidence_items, "poam": [item.to_dict() for item in poam], "disclaimer": CMMC_DISCLAIMER}
    artifact_dir = context.output_dir / f"cmmc_artifacts_{uuid4().hex[:10]}"
    path = artifact_dir / "cmmc_readiness_payload.json"
    try:
        artifact_dir.mkdir(parents=True, exist_ok=False)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        return [check.failed(
            "CMMC report artifact directory could not be written.",
            "Repair Pre-UAT report directory permissions or remove stale protected CMMC artifacts, then rerun the audit.",
            {"artifact_dir": str(artifact_dir), "exception": type(exc).__name__, "error": str(exc)},
        )]
    if not payload["evidence_matrix"] or not payload["poam"]:
        return [check.failed("CMMC report payload missing Evidence Matrix or POA&M.", "Include CMMC Summary, Evidence Matrix, POA&M, source versions, and disclaimer in reports.", {"path": str(path)})]
    assessment = SecurityAssessment(
        assessment_id="cmmc-pre-uat",
        created_at="2026-07-05T00:00:00+00:00",
        hostname="pre-uat",
        macos_version="test",
        app_version="test",
        assessment_status="ready",
        overall_score=90,
        risk_level="low",
        executive_summary="CMMC readiness report export validation.",
        cmmc_readiness=readiness.to_dict(),
        limitations=["CMMC scope must be confirmed by authorized organizational personnel."],
    )
    html_path = export_security_assessment_html(assessment, artifact_dir / "cmmc_assessment.html")
    json_path = export_security_assessment_json(assessment, artifact_dir / "cmmc_assessment.json")
    html_text = html_path.read_text(encoding="utf-8")
    json_text = json_path.read_text(encoding="utf-8")
    missing = []
    for label, text, expected_values in [
        ("html", html_text, ["CMMC Readiness Summary", "Source Versions", "Evidence Matrix"]),
        ("json", json_text, ["cmmc_readiness", "source_versions", "evidence_items"]),
    ]:
        for expected in expected_values:
            if expected not in text:
                missing.append(f"{label}:{expected}")
    if missing:
        core = check.failed("CMMC core exports are missing required sections.", "Ensure HTML and JSON include CMMC summary, evidence matrix, POA&M, and source versions.", {"missing": missing})
    else:
        core = check.passed("CMMC core assessment and HTML/JSON exports succeeded without Office dependencies.", {"payload": str(path), "html": str(html_path), "json": str(json_path), "evidence_items": len(payload["evidence_matrix"]), "poam_items": len(payload["poam"])})
    return [core, _office_format_check(assessment, artifact_dir, "word"), _office_format_check(assessment, artifact_dir, "excel")]


def _office_format_check(assessment: SecurityAssessment, artifact_dir: Path, format_name: str) -> FunctionalCheck:
    check = FunctionalCheck(f"frameworks.cmmc_{format_name}", "Framework Readiness", f"CMMC {format_name.title()} artifact", f"The optional CMMC {format_name.title()} artifact is generated when its Office dependency is available.", "medium", "framework")
    try:
        if format_name == "word":
            from mac_audit_agent.exporters.word_exporter import export_assessment_word
            path = export_assessment_word(assessment, artifact_dir / "cmmc_assessment.docx")
            with zipfile.ZipFile(path) as archive:
                valid = "CMMC / NIST Readiness" in archive.read("word/document.xml").decode("utf-8")
        else:
            from mac_audit_agent.exporters.excel_exporter import export_assessment_excel
            path = export_assessment_excel(assessment, artifact_dir / "cmmc_assessment.xlsx")
            with zipfile.ZipFile(path) as archive:
                workbook = archive.read("xl/workbook.xml").decode("utf-8")
                valid = all(sheet in workbook for sheet in ["CMMC Summary", "Evidence Matrix", "POA&amp;M", "Source Versions"])
    except OptionalDependencyError as exc:
        return check.degraded(f"Optional {format_name.title()} artifact was not generated: {exc}", str(exc), {"format": format_name, "generated": False, "error_code": exc.error_code, "distribution": exc.distribution_name, "required": exc.required_version})
    if not valid:
        return check.failed(f"CMMC {format_name.title()} artifact is missing required sections.", f"Correct the {format_name.title()} exporter CMMC sections.", {"path": str(path), "generated": True})
    return check.passed(f"CMMC {format_name.title()} artifact includes required sections.", {"path": str(path), "generated": True})


def _no_false_claims_check() -> FunctionalCheck:
    check = FunctionalCheck("frameworks.no_false_claims", "Framework Readiness", "unsupported standards wording", "No unsupported certification, endorsement, or approval wording appears.", "blocker", "framework")
    return _false_claims_check(check)


def _standards_no_false_claims_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.no_false_claims", "Framework Readiness", "unsupported standards wording", "No unsupported certification, endorsement, or approval wording appears.", "blocker", "framework")
    return _false_claims_check(check)


def _false_claims_check(check: FunctionalCheck) -> FunctionalCheck:
    paths = list(Path("mac_audit_agent").rglob("*.py")) + list(Path("docs").glob("*.md")) + [Path("README.md")]
    matches = []
    for path in paths:
        if not path.exists():
            continue
        if path.name in {"cmmc_auditor.py", "report_conformance.py"} or "tests" in path.parts:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            lowered = line.lower()
            explicit_negation = bool(re.search(r"\b(?:is|are|does|do)\s+not\b", lowered))
            for phrase in FORBIDDEN_WORDING:
                phrase_lower = phrase.lower()
                if phrase_lower in lowered and not explicit_negation and f"not {phrase_lower}" not in lowered:
                    matches.append(f"{path}:{phrase}")
    if matches:
        return check.failed("Unsupported certification/compliance wording found.", "Replace with readiness/evidence-support wording and disclaimers.", {"matches": matches[:25]})
    return check.passed("No unsupported certification/compliance wording found.", {"phrases_checked": FORBIDDEN_WORDING})


def _accepted_ideas_have_mappings_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.accepted_ideas_have_mappings", "Framework Readiness", "accepted idea mappings", "Accepted derivative ideas include official source IDs, mapping confidence, and design specs.", "high", "framework")
    matrix = Path("docs/STANDARDS_DERIVED_IMPROVEMENT_MATRIX.md")
    specs_dir = Path("docs/derived_features")
    if not matrix.exists():
        return check.failed("Standards-derived matrix is missing.", "Create the idea matrix before accepting derivative improvements.", {})
    text = matrix.read_text(encoding="utf-8", errors="replace")
    accepted_lines = [line for line in text.splitlines() if line.startswith("| SDI-") and "| yes |" in line.lower()]
    if not accepted_lines:
        return check.failed("No accepted ideas found.", "Mark only standards-backed low-copy-risk ideas as accepted_for_implementation = yes.", {})
    missing = []
    for line in accepted_lines:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        idea_id = cells[0] if cells else "unknown"
        if len(cells) < 15 or not cells[5] or not cells[6]:
            missing.append(f"{idea_id}:mapping_fields")
        if not specs_dir.exists() or not list(specs_dir.glob(f"{idea_id}_*.md")):
            missing.append(f"{idea_id}:design_spec")
    if missing:
        return check.failed("Accepted ideas are missing mappings or design specs.", "Add official source IDs, confidence values, and docs/derived_features specs.", {"missing": missing})
    return check.passed("Accepted derivative ideas include standards mappings and MSAA-native design specs.", {"accepted_ideas": len(accepted_lines), "spec_dir": str(specs_dir)})


def _nsa_acknowledgement_check() -> FunctionalCheck:
    check = FunctionalCheck("acknowledgements.nsa_separate_from_author", "Framework Readiness", "NSA acknowledgement separation", "NSA thank-you is separate from author/support/donation wording.", "blocker", "framework")
    docs_text = Path("docs/ACKNOWLEDGEMENTS.md").read_text(encoding="utf-8", errors="replace") if Path("docs/ACKNOWLEDGEMENTS.md").exists() else ""
    ui_text = Path("mac_audit_agent/ui/main_window.py").read_text(encoding="utf-8", errors="replace")
    combined = docs_text + "\n" + ui_text
    required = [
        "Author / Developer",
        "Liquidsky Network Security",
        "Community Acknowledgements",
        "Thank you to the NSA",
        "does not imply endorsement, affiliation, certification, or approval",
    ]
    missing = [item for item in required if item not in combined]
    if missing:
        return check.failed("NSA acknowledgement is missing required separation/disclaimer text.", "Keep NSA acknowledgement separate from author and support links.", {"missing": missing})
    donation_window = ui_text[ui_text.find("Community Acknowledgements"):ui_text.find("def _open_support_link")]
    if "Patreon" in donation_window or "Buy Me a Coffee" in donation_window:
        return check.failed("NSA acknowledgement appears near donation link wording.", "Move acknowledgement away from donation/support link controls.", {})
    return check.passed("NSA acknowledgement is separate from author and donation/support sections.", {})


def _support_author_final_tab_check() -> FunctionalCheck:
    check = FunctionalCheck("support_author.final_tab", "UI", "Support the Author final tab", "Support the Author navigation item remains pinned last.", "high", "framework")
    try:
        from mac_audit_agent.ui.navigation_registry import NavigationItem, ordered_navigation_items, validate_navigation_order

        items = [
            NavigationItem("dashboard", "Dashboard", order=10),
            NavigationItem("future", "Future Feature", order=9998),
            NavigationItem("support_author", "Support the Author", order=9999, pinned_position="last"),
        ]
        ordered = ordered_navigation_items(items)
        errors = validate_navigation_order(ordered)
        if errors or ordered[-1].id != "support_author":
            return check.failed("Support the Author is not guaranteed as the final tab.", "Keep support_author pinned_position='last' and validate navigation order.", {"errors": errors, "ordered": [item.id for item in ordered]})
        return check.passed("Support the Author remains pinned as the final navigation item.", {"ordered": [item.id for item in ordered]})
    except Exception as exc:
        return check.failed(str(exc), "Fix navigation registry validation.", {"exception": type(exc).__name__})


def _manual_evidence_check() -> FunctionalCheck:
    check = FunctionalCheck("frameworks.cmmc_manual_evidence", "Framework Readiness", "manual evidence identification", "Manual/process CMMC evidence requirements are identified.", "high", "framework")
    manual = [item for item in cmmc_requirements() if item.limitations]
    if not manual:
        return check.failed("No manual evidence requirements identified.", "Mark policy/process requirements as manual_review_required instead of automatically met.", {})
    auto_met_manual = [item.cmmc_id for item in manual if item.implementation_status == "met"]
    if auto_met_manual:
        return check.failed("Manual evidence requirements are marked met automatically.", "Manual/process controls must require analyst evidence.", {"auto_met": auto_met_manual})
    return check.passed("Manual evidence requirements are separated from local technical scan evidence.", {"manual_requirements": [item.cmmc_id for item in manual]})


def _contractual_profile_separated_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.contractual_profile_separated", "Framework Readiness", "contractual and future profile isolation", "Final future standards cannot drive current contractual CMMC scoring.", "blocker", "framework")
    future = validate_profile_isolation("nist_171_r3_future", requested_for_current_score=True)
    current = validate_profile_isolation("cmmc_l2_current", requested_for_current_score=False)
    current_scoring = validate_profile_isolation("cmmc_l2_current", requested_for_current_score=True)
    if future["allowed"] or not current["allowed"] or current_scoring["allowed"]:
        return check.failed("Standards profile isolation failed.", "Keep Rev. 3 future-readiness results separate from the contractual Rev. 2 CMMC score.", {"current": current, "future": future})
    return check.passed("Current contractual and final future-readiness profiles are isolated; incomplete current content is not scoring-active.", {"current": current, "current_scoring": current_scoring, "future": future})


def _catalog_completeness_check() -> FunctionalCheck:
    check = FunctionalCheck("standards.catalog_complete_level2", "Framework Readiness", "complete CMMC Level 2 catalog", "All 110 current Level 2 requirements and their objectives are represented.", "blocker", "framework")
    requirements = [item.practice_id for item in cmmc_requirements() if item.level == 2]
    validation = validate_catalog("cmmc_l2_current", requirements, requirements)
    if not validation["complete"]:
        return check.failed("[STD004] The bundled Level 2 catalog is incomplete.", "Install and explicitly activate a human-reviewed official Level 2 content pack. Assessment work may continue, but no complete Level 2 result or score may be issued.", validation)
    return check.passed("The active Level 2 catalog is complete.", validation)


def _no_invented_score_check() -> FunctionalCheck:
    check = FunctionalCheck("scoring.level2_methodology_valid", "Framework Readiness", "official Level 2 scoring only", "Incomplete mappings never emit a generic percentage or invented partial credit.", "blocker", "framework")
    readiness = build_cmmc_readiness(target_level=2, completed_check_ids={"scan.apple_exposure"})
    if readiness.readiness_score is not None:
        return check.failed("An incomplete evidence mapping emitted a score.", "Disable generic percentages and use only a complete, sourced official scoring rule pack.", {"score": readiness.readiness_score})
    return check.passed("Incomplete readiness mappings fail closed without an unofficial score.", {"score": None, "catalog_complete": False})


def _scope_workflow_gate_check() -> FunctionalCheck:
    check = FunctionalCheck("scope.cui_boundary_complete", "Assessment Scope", "validated CUI boundary", "Contract applicability, assets, flows, providers, suppliers, and unresolved questions are complete.", "blocker", "framework")
    return check.failed("[SCP001] No reviewed assessment scope is attached to this run.", "Create or import a contract-linked scope, categorize every asset using the active guide, map CUI/FCI flows and providers, and obtain reviewer disposition for unresolved questions. Framework analysis may continue, but no final readiness result may be issued.", {"assessment_can_continue": True, "final_result_allowed": False, "manual_fallback": "Attach an assessor-reviewed scope workbook and register its evidence hash."})


def _assessment_methods_gate_check() -> FunctionalCheck:
    check = FunctionalCheck("assessment.objective_determinations_consistent", "Assessment Methods", "objective method and determination completeness", "Every applicable objective has examine/interview/test planning, evidence, analyst disposition, and reviewer signoff.", "blocker", "framework")
    return check.failed("[ASM001] The active objective catalog and method plan are incomplete.", "Install the reviewed objective content pack, build examine/interview/test plans, attach evidence, and complete reviewer signoff. Do not translate technical-check success into MET.", {"applicable_objectives_known": False, "manual_evidence_auto_pass": False, "final_result_allowed": False})


def _report_conformance_gate_check() -> FunctionalCheck:
    check = FunctionalCheck("reports.level2_conformant", "Reporting", "Level 2 report conformance", "The Level 2 report contains complete requirements, objectives, methods, evidence, determinations, source hashes, scope, and signoffs.", "blocker", "framework")
    readiness = build_cmmc_readiness(target_level=2)
    payload = {"header": {"report_title": "CMMC Level 2 assessment readiness", "disclaimer": CMMC_DISCLAIMER}, "requirements": [{"requirement_id": item["practice_id"], "determination": "NOT_ASSESSED"} for item in readiness.requirements], "objectives": [], "profiles_separated": True}
    result = evaluate_report(payload, expected_requirements=110, expected_objectives=None)
    if result.status in {ConformanceStatus.CONFORMANT, ConformanceStatus.CONFORMANT_WITH_LIMITATIONS}:
        return check.passed("Level 2 report is conformant.", result.to_dict())
    return check.failed(f"[RPT001] Level 2 report status is {result.status}.", "Complete the catalog, universal header, scope, methods, evidence index, determinations, scoring integrity, and reviewer signoffs before issuing a conformant report.", result.to_dict())


def _incident_no_submission_check() -> FunctionalCheck:
    check = FunctionalCheck("incident.no_automatic_submission", "Incident Response", "no automatic government submission", "Incident workflows prepare reviewable packages without submitting to DIBNet, DC3, SPRS, or eMASS.", "blocker", "framework")
    source = Path("mac_audit_agent/frameworks/incident_readiness.py").read_text(encoding="utf-8")
    forbidden = [token for token in ("requests.post", "urlopen(", "subprocess.run") if token in source]
    if forbidden:
        return check.failed("Incident workflow contains a transmission primitive.", "Remove automatic transmission and require explicit external authorized submission.", {"forbidden": forbidden})
    return check.passed("Incident workflow is preparation-only and contains no submission primitive.", {"submission_performed": False})


def _roadmap_complete_check() -> FunctionalCheck:
    check = FunctionalCheck("roadmap.product_feature_gaps_complete", "Roadmap", "machine-readable feature-gap register", "Every known assessment blocker is represented with priority, fallback, risks, acceptance tests, status, and owner.", "high", "framework")
    path = Path("docs/COMPLIANCE_FEATURE_GAP_REGISTER.json")
    required = {"feature_gap_id", "title", "description", "affected_frameworks", "affected_requirements", "affected_objectives", "current_capability", "missing_capability", "evidence_impact", "assessment_impact", "contractual_impact", "recommended_solution", "alternative_solutions", "manual_fallback", "priority", "implementation_effort", "dependencies", "security_risks", "privacy_risks", "acceptance_tests", "proposed_release", "status", "owner"}
    if not path.is_file():
        return check.failed("Feature-gap register is missing.", "Create the machine-readable register.", {})
    items = json.loads(path.read_text(encoding="utf-8")).get("items", [])
    invalid = [item.get("feature_gap_id", "unknown") for item in items if required - set(item)]
    if not items or invalid:
        return check.failed("Feature-gap register is incomplete.", "Populate every required field and retain PLANNED/RESEARCH status for unimplemented work.", {"invalid": invalid})
    return check.passed("Feature-gap register is structurally complete and distinguishes planned/research work.", {"items": len(items), "statuses": sorted({item["status"] for item in items})})


__all__ = ["run_cmmc_audit"]
