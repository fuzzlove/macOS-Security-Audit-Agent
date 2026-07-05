from __future__ import annotations

from mac_audit_agent.quality.export_auditor import run_export_audit


def run_report_audit(context):
    return run_export_audit(context)


__all__ = ["run_report_audit"]
