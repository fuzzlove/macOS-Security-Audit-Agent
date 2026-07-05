from __future__ import annotations

from mac_audit_agent.quality.scan_auditor import _freshness_check


def run_freshness_audit(context):
    return [_freshness_check(context)]


__all__ = ["run_freshness_audit"]
