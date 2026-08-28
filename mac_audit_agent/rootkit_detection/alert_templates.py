from __future__ import annotations


ROOTKIT_ALERT_TEMPLATES: dict[str, dict[str, str]] = {
    "rootkit_suspect_detected": {
        "title": "Rootkit-Like Suspect Indicators",
        "summary": "MSAA correlated advanced persistence or visibility indicators that require review.",
        "recommended_action": "Open Rootkit & Advanced Persistence Review and preserve evidence before remediation.",
        "severity": "critical",
    },
    "hidden_port_mismatch_detected": {
        "title": "Hidden Port Visibility Mismatch",
        "summary": "A local listener was visible in one tool but lacked consistent ownership visibility.",
        "recommended_action": "Re-run local port checks and review the owning process evidence.",
        "severity": "high",
    },
    "suspicious_kernel_extension_detected": {
        "title": "Suspicious Kernel Extension",
        "summary": "A kernel extension has attributes that require advanced persistence review.",
        "recommended_action": "Verify Team ID, signature, path, permissions, and install source.",
        "severity": "high",
    },
    "suspicious_system_extension_detected": {
        "title": "Suspicious System Extension",
        "summary": "A system, network, DriverKit, or Endpoint Security extension requires review.",
        "recommended_action": "Verify the extension owner, purpose, signature, and approval record.",
        "severity": "high",
    },
    "system_integrity_weakened": {
        "title": "System Integrity Weakened",
        "summary": "A macOS integrity protection appears disabled or weakened.",
        "recommended_action": "Review why the protection is disabled and preserve evidence before changing system posture.",
        "severity": "high",
    },
    "persistence_network_correlation_detected": {
        "title": "Persistence and Network Correlation",
        "summary": "Persistence and network indicators were correlated for high-priority review.",
        "recommended_action": "Inspect persistence configuration, listener ownership, signatures, and event timelines.",
        "severity": "critical",
    },
    "visibility_mismatch_detected": {
        "title": "Visibility Mismatch Detected",
        "summary": "Local visibility sources disagree on a process, extension, file, or network component.",
        "recommended_action": "Repeat collection close together in time and review permission or race-condition explanations.",
        "severity": "high",
    },
    "dylib_hijack_detected": {
        "title": "Possible Dynamic Library Hijack",
        "summary": "A running executable has a suspicious dynamic-library resolution condition requiring immediate review.",
        "recommended_action": "Preserve the executable and library evidence, verify signatures and Team IDs, and review related process and persistence events.",
        "severity": "high",
    },
}


def required_rootkit_alert_events() -> set[str]:
    return set(ROOTKIT_ALERT_TEMPLATES)
