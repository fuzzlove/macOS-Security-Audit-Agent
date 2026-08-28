from __future__ import annotations

from mac_audit_agent.persistence_intelligence.models import PersistenceScanReport


def build_diagnostics(report: PersistenceScanReport) -> dict:
    coverage_by_id = {str(row.get("scanner_id", "")): row for row in report.coverage}
    scanner_diagnostics = []
    for result in report.scanner_results:
        coverage = coverage_by_id.get(result.scanner_id, {})
        status = str(coverage.get("coverage_status", result.coverage_status or "unknown")).lower()
        if result.errors:
            cause = "Scanner failed: " + "; ".join(result.errors)
            investigation = "Resolve the exact collector errors and required permissions, manually validate missed paths, then rerun."
            passing_criteria = "Scanner completes with no errors and all expected persistence locations are observable."
        elif result.warnings:
            cause = "Coverage is partial/degraded: " + "; ".join(result.warnings)
            investigation = "Review every warning, validate unreadable locations manually, and grant only approved read access where required."
            passing_criteria = "Warnings are resolved or formally accepted with documented compensating manual evidence."
        elif status in {"healthy", "clean", "pass", "passed", "complete"}:
            cause = f"Scanner passed collection with no reported warnings/errors; {len(result.items)} item(s) and {len(result.findings)} finding(s) recorded."
            investigation = "Investigate recorded findings separately and confirm evidence freshness."
            passing_criteria = "Retain complete, current collection; a scanner pass does not assert that every observed item is safe."
        else:
            cause = f"Scanner reported {status or 'unknown'} without a detailed warning/error."
            investigation = "Treat as not passing; review collector availability and validate this persistence surface manually."
            passing_criteria = "Scanner must report a complete/healthy state or have documented compensating evidence."
        scanner_diagnostics.append({
            "scanner_id": result.scanner_id,
            "rating": status,
            "cause": cause,
            "what_to_investigate": investigation,
            "passing_criteria": passing_criteria,
            "warnings": list(result.warnings),
            "errors": list(result.errors),
            "affected_item_count": len(result.items),
            "affected_finding_count": len(result.findings),
            "requires_full_disk_access": bool(coverage.get("requires_full_disk_access", False)),
            "requires_root": bool(coverage.get("requires_root", False)),
            "unreadable_paths": list(coverage.get("unreadable_paths", [])),
        })
    return {
        "scan_id": report.scan_id,
        "posture_score": report.posture_score,
        "scanner_count": len(report.scanner_results),
        "item_count": len(report.items),
        "finding_count": len(report.findings),
        "warning_count": sum(len(result.warnings) for result in report.scanner_results),
        "error_count": sum(len(result.errors) for result in report.scanner_results),
        "coverage": report.coverage,
        "scanner_diagnostics": scanner_diagnostics,
        "safety": {
            "scan_is_read_only": True,
            "guarded_remediation_exposed": True,
            "remediation_mode": "explicit user-authorized backup and quarantine with protected-system refusal",
            "automatic_remediation": False,
        },
    }
