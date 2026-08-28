from __future__ import annotations

from typing import Any

from .lockdown_enforcement import LockdownEnforcer


def rollback_controls(controls: list[dict[str, Any]], enforcer: LockdownEnforcer, *, dry_run: bool = False) -> list[dict[str, Any]]:
    results = []
    for control in reversed(controls):
        result = enforcer.rollback(control, dry_run=dry_run)
        results.append(result.to_dict())
        if not result.success: break
    return results
