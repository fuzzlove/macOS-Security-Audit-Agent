from __future__ import annotations

from typing import Any


def tcc_remediation_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    application = finding.get("process_name") or finding.get("bundle_id") or finding.get("path") or "the reviewed application"
    return {
        "direct_database_modification": False,
        "remaining_action_required": True,
        "application": application,
        "steps": [
            "Open System Settings.",
            "Select Privacy & Security.",
            "Review Accessibility, Input Monitoring, Screen Recording, and Automation.",
            f"Remove or disable {application} only after confirming it is not required.",
            "Restart affected applications or the Mac if macOS requests it, then rescan.",
        ],
        "note": "MSAA does not edit TCC.db. Privacy decisions must use Apple-supported System Settings or approved MDM/PPPC workflows.",
    }


__all__ = ["tcc_remediation_guidance"]
