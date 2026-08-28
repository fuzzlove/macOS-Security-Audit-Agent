from __future__ import annotations

from mac_audit_agent.rootkit_detection.diagnostics import run_rootkit_review
from mac_audit_agent.rootkit_detection.kernel_surface import KernelSurfaceAssessment, analyze_kext_plist, scan_binary_capabilities
from mac_audit_agent.rootkit_detection.models import (
    ExtensionInventoryItem,
    PortVisibilityFinding,
    RootkitScanResult,
    RootkitSuspectFinding,
    SystemIntegrityPosture,
    VisibilityMismatch,
)

__all__ = [
    "ExtensionInventoryItem",
    "PortVisibilityFinding",
    "RootkitScanResult",
    "RootkitSuspectFinding",
    "SystemIntegrityPosture",
    "VisibilityMismatch",
    "KernelSurfaceAssessment",
    "analyze_kext_plist",
    "scan_binary_capabilities",
    "run_rootkit_review",
]
