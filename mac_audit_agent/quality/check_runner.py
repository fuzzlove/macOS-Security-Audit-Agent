from __future__ import annotations

from mac_audit_agent.quality.audit_models import AuditContext, AuditReport
from mac_audit_agent.quality.pre_uat_audit import run_pre_uat_audit


def run_checks(context: AuditContext) -> AuditReport:
    return run_pre_uat_audit(context)


__all__ = ["run_checks"]
