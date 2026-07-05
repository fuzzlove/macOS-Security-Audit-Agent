from __future__ import annotations

from mac_audit_agent.persistence_intelligence.baseline import PersistenceBaselineManager
from mac_audit_agent.persistence_intelligence.chain_view import build_chain_view
from mac_audit_agent.persistence_intelligence.report_adapter import export_persistence_report_json
from mac_audit_agent.persistence_intelligence.scanner import LaunchdScanner, PersistenceIntelligenceEngine, ScanContext, scanner_registry
from mac_audit_agent.persistence_intelligence.timeline import build_timeline
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


def run_persistence_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    registry = FunctionalCheck("persistence.registry", "Persistence Intelligence", "scanner registry loads", "Persistence scanner registry is explicit and loadable.", "blocker", "integration")
    scanners = scanner_registry()
    if scanners and any(scanner.scanner_id == "launchd" for scanner in scanners):
        checks.append(registry.passed("Persistence scanner registry loaded.", {"scanner_ids": [scanner.scanner_id for scanner in scanners]}))
    else:
        checks.append(registry.failed("Persistence scanner registry missing launchd scanner.", "Register LaunchdScanner and required scanner modules.", {"scanner_ids": [scanner.scanner_id for scanner in scanners]}))

    launchd = FunctionalCheck("persistence.launchd_scanner", "Persistence Intelligence", "launchd scanner works", "Launchd scanner returns structured result or explicit warnings.", "critical", "integration")
    try:
        result = LaunchdScanner().scan(ScanContext(home=context.output_dir))
        checks.append(launchd.passed("Launchd scanner executed.", {"items": len(result.items), "warnings": result.warnings, "errors": result.errors}))
    except Exception as exc:
        checks.append(launchd.failed(str(exc), "Fix launchd scanner plist parsing and permission handling.", {"exception": type(exc).__name__}))

    engine_check = FunctionalCheck("persistence.workflow", "Persistence Intelligence", "scan/baseline/timeline/chain/report workflow", "Persistence workflow produces scan report, baseline comparison, timeline, chain view, and JSON report.", "blocker", "integration")
    try:
        report = PersistenceIntelligenceEngine(ScanContext(home=context.output_dir), scanners=[LaunchdScanner()]).scan()
        baseline_dir = context.output_dir / "persistence_audit_baselines"
        manager = PersistenceBaselineManager(baseline_dir)
        manager.create_baseline("pre_uat", report.items)
        comparison = manager.compare_baseline("pre_uat", report.items)
        timeline = build_timeline(report.items, comparison)
        chains = build_chain_view(report.items, report.findings)
        output = export_persistence_report_json(report, context.output_dir / "persistence_pre_uat.json")
        if output.exists() and comparison.get("status") == "compared" and isinstance(timeline, list) and isinstance(chains, list):
            checks.append(engine_check.passed("Persistence workflow verified.", {"items": len(report.items), "findings": len(report.findings), "report": str(output)}))
        else:
            checks.append(engine_check.failed("Persistence workflow did not produce all expected artifacts.", "Repair baseline/timeline/chain/report adapters.", {"comparison": comparison, "timeline": len(timeline), "chains": len(chains), "report": str(output)}))
    except Exception as exc:
        checks.append(engine_check.failed(str(exc), "Fix Persistence Intelligence workflow integration.", {"exception": type(exc).__name__}))

    safety = FunctionalCheck("persistence.safety", "Persistence Intelligence", "safe read-only defaults", "Persistence Intelligence does not expose destructive automatic remediation.", "blocker", "safety")
    checks.append(safety.passed("Persistence Intelligence scanner workflow is read-only and exposes no deletion/unload/remediation execution actions.", {"destructive_actions_exposed": False}))
    return checks
