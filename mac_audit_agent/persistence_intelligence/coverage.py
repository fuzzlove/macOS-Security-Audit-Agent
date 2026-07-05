from __future__ import annotations

from mac_audit_agent.persistence_intelligence.models import ScannerResult


def coverage_from_results(results: list[ScannerResult]) -> list[dict]:
    coverage = []
    for result in results:
        if result.errors:
            status = "failed"
        elif result.warnings:
            status = "partial"
        else:
            status = result.coverage_status or "healthy"
        coverage.append({
            "scanner_id": result.scanner_id,
            "enabled": True,
            "last_run": "",
            "item_count": len(result.items),
            "finding_count": len(result.findings),
            "warning_count": len(result.warnings),
            "error_count": len(result.errors),
            "requires_full_disk_access": any("Full Disk Access" in warning for warning in result.warnings),
            "requires_root": any("permission" in warning.lower() for warning in result.warnings),
            "unreadable_paths": [warning for warning in result.warnings if "unreadable" in warning.lower() or "permission" in warning.lower()],
            "coverage_status": status,
        })
    return coverage
