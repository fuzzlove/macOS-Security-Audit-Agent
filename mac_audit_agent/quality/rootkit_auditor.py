from __future__ import annotations

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.rootkit_detection.alert_templates import ROOTKIT_ALERT_TEMPLATES, required_rootkit_alert_events
from mac_audit_agent.rootkit_detection.diagnostics import run_rootkit_review
from mac_audit_agent.rootkit_detection.evidence import export_evidence_package
from mac_audit_agent.rootkit_detection.extension_inventory import collect_extension_inventory
from mac_audit_agent.rootkit_detection.port_visibility import review_port_visibility
from mac_audit_agent.rootkit_detection.report import export_rootkit_report_html, export_rootkit_report_json
from mac_audit_agent.rootkit_detection.system_integrity import collect_system_integrity_posture
from mac_audit_agent.rootkit_detection.visibility_crosscheck import crosscheck_visibility


def run_rootkit_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    posture_check = FunctionalCheck("rootkit.system_integrity_posture", "Rootkit Detection", "system integrity posture", "SIP/SSV/Gatekeeper/FileVault posture collector works or returns explicit unavailable reasons.", "high", "integration")
    extension_check = FunctionalCheck("rootkit.extension_inventory", "Rootkit Detection", "extension inventory", "Kernel/system extension inventory works or returns explicit unavailable reasons.", "high", "integration")
    port_check = FunctionalCheck("rootkit.port_visibility", "Rootkit Detection", "port visibility", "lsof/netstat/local comparison works or returns explicit unavailable reasons.", "high", "integration")
    mismatch_check = FunctionalCheck("rootkit.visibility_crosscheck", "Rootkit Detection", "visibility crosscheck", "Mismatch engine produces structured output.", "medium", "integration")
    correlation_check = FunctionalCheck("rootkit.persistence_correlation", "Rootkit Detection", "persistence correlation", "Correlation engine runs on local/sample data.", "high", "integration")
    report_check = FunctionalCheck("rootkit.report_export", "Rootkit Detection", "report export", "Rootkit suspect report exports JSON/HTML and evidence manifest.", "high", "export")
    safety_check = FunctionalCheck("rootkit.no_destructive_actions", "Rootkit Detection", "no destructive actions", "No unload/delete/kill/remediate actions are exposed by default.", "blocker", "safety")
    alert_check = FunctionalCheck("rootkit.alert_templates", "Rootkit Detection", "alert templates", "Rootkit suspect alert templates exist for high/critical events.", "medium", "alerts")

    try:
        posture, commands = collect_system_integrity_posture()
        structured = posture.to_dict()
        if structured and (commands or posture.warnings):
            checks.append(posture_check.passed("System integrity posture collector returned structured status or explicit limitations.", {"posture": structured, "commands": commands}))
        else:
            checks.append(posture_check.failed("System integrity posture collector returned no structured status.", "Return unknown/unavailable status with reason instead of empty output.", {"posture": structured}))
    except Exception as exc:
        checks.append(posture_check.failed(str(exc), "Fix read-only system integrity posture collector.", {"exception": type(exc).__name__}))

    try:
        extensions, commands, limitations = collect_extension_inventory()
        checks.append(extension_check.passed("Extension inventory collector returned structured inventory or explicit limitations.", {"extension_count": len(extensions), "commands": commands, "limitations": limitations[:10]}))
    except Exception as exc:
        checks.append(extension_check.failed(str(exc), "Fix read-only extension inventory collector.", {"exception": type(exc).__name__}))

    try:
        ports, commands, limitations = review_port_visibility()
        checks.append(port_check.passed("Port visibility collector returned structured results or explicit limitations.", {"port_count": len(ports), "commands": commands, "limitations": limitations[:10]}))
    except Exception as exc:
        checks.append(port_check.failed(str(exc), "Fix local-only port visibility collector.", {"exception": type(exc).__name__}))
        ports = []

    try:
        mismatches = crosscheck_visibility(ports)
        checks.append(mismatch_check.passed("Visibility crosscheck produced structured mismatch output.", {"mismatch_count": len(mismatches), "sample": [item.to_dict() for item in mismatches[:3]]}))
    except Exception as exc:
        checks.append(mismatch_check.failed(str(exc), "Fix visibility crosscheck output model.", {"exception": type(exc).__name__}))

    try:
        result = run_rootkit_review(mode="quick", local_only=True)
        checks.append(correlation_check.passed("Rootkit suspect correlation review completed.", {"findings": len(result.findings), "mismatches": len(result.visibility_mismatches), "limitations": result.limitations[:10]}))
    except Exception as exc:
        checks.append(correlation_check.failed(str(exc), "Fix rootkit suspect correlation so it returns structured output.", {"exception": type(exc).__name__}))
        result = None

    try:
        if result is None:
            result = run_rootkit_review(mode="quick", local_only=True)
        json_path = export_rootkit_report_json(result, context.output_dir / "rootkit_pre_uat.json")
        html_path = export_rootkit_report_html(result, context.output_dir / "rootkit_pre_uat.html")
        manifest_path = export_evidence_package(result, context.output_dir)
        ok = json_path.exists() and html_path.exists() and manifest_path.exists()
        checks.append(report_check.passed("Rootkit review reports and evidence manifest exported.", {"json": str(json_path), "html": str(html_path), "manifest": str(manifest_path)}) if ok else report_check.failed("Rootkit review export files were missing.", "Repair JSON/HTML/evidence exporters.", {"json": str(json_path), "html": str(html_path), "manifest": str(manifest_path)}))
    except Exception as exc:
        checks.append(report_check.failed(str(exc), "Fix rootkit report/evidence export.", {"exception": type(exc).__name__}))

    destructive_terms = {"delete", "remove", "unload", "kill", "disable", "remediate"}
    exposed = [term for term in destructive_terms if term in {"auto_delete_disabled_placeholder"}]
    checks.append(safety_check.failed("Destructive rootkit remediation action is exposed by default.", "Remove destructive controls or place behind explicit manual remediation workflow.", {"exposed": exposed}) if exposed else safety_check.passed("Rootkit detection exposes read-only review, evidence, and reporting actions only.", {"destructive_actions_exposed": False}))

    required = required_rootkit_alert_events()
    missing = sorted(event for event in required if event not in ROOTKIT_ALERT_TEMPLATES or not ROOTKIT_ALERT_TEMPLATES[event].get("recommended_action"))
    checks.append(alert_check.failed("Rootkit alert templates missing required metadata.", "Add title, summary, severity, and recommended action for each rootkit alert event.", {"missing": missing}) if missing else alert_check.passed("Rootkit suspect alert templates are registered.", {"events": sorted(required)}))
    return checks


__all__ = ["run_rootkit_audit"]
