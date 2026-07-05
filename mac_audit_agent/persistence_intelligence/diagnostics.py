from __future__ import annotations

from mac_audit_agent.persistence_intelligence.models import PersistenceScanReport


def build_diagnostics(report: PersistenceScanReport) -> dict:
    return {
        "scan_id": report.scan_id,
        "posture_score": report.posture_score,
        "scanner_count": len(report.scanner_results),
        "item_count": len(report.items),
        "finding_count": len(report.findings),
        "warning_count": sum(len(result.warnings) for result in report.scanner_results),
        "error_count": sum(len(result.errors) for result in report.scanner_results),
        "coverage": report.coverage,
        "safety": {
            "read_only": True,
            "destructive_actions_exposed": False,
            "automatic_remediation": False,
        },
    }
