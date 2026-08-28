"""Read-only recovery readiness analysis."""

import shutil


def analyze_recovery_readiness() -> dict:
    tmutil = shutil.which("tmutil") is not None
    return {"time_machine_tool_available": tmutil, "backup_contents_inspected": False,
            "status": "review_required" if not tmutil else "technical_check_available",
            "guidance": "Verify offline or immutable backups and test restoration through an authorized process."}


__all__ = ["analyze_recovery_readiness"]
