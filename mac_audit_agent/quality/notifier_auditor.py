from __future__ import annotations

from mac_audit_agent.quality.daemon_auditor import run_daemon_audit


def run_notifier_audit(context):
    return [check for check in run_daemon_audit(context) if "notifier" in check.check_id or "notifier" in check.name.lower()]


__all__ = ["run_notifier_audit"]
