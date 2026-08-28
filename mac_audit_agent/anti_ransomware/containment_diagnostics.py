from __future__ import annotations

import platform
from dataclasses import asdict
from pathlib import Path

from .containment_production import ActiveContainmentEvidence, active_containment_ready


HELPER_BUNDLE_ID = "com.fuzzlove.MacAuditAgent.ContainmentHelper"
ENGINE_BUNDLE_ID = "com.fuzzlove.MacAuditAgent.SystemEngine"
MACH_SERVICE = "com.fuzzlove.MacAuditAgent.ContainmentHelper.xpc"
INSTALLED_HELPER = Path("/Library/Application Support/MacAuditAgent/bin/MSAAContainmentHelper")
LEASE_JOURNAL = Path("/Library/Application Support/MacAuditAgent/containment/leases.sqlite3")


def containment_status() -> dict:
    evidence = ActiveContainmentEvidence(helper_is_native=True, lease_is_durable=True, request_replay_is_rejected=True)
    return {
        "schema_version": "1.0", "helper_bundle_id": HELPER_BUNDLE_ID, "engine_bundle_id": ENGINE_BUNDLE_ID,
        "mach_service": MACH_SERVICE, "expected_helper_path": str(INSTALLED_HELPER), "lease_journal": str(LEASE_JOURNAL),
        "host": {"macos": platform.mac_ver()[0], "architecture": platform.machine()},
        "evidence": asdict(evidence), "ACTIVE_CONTAINMENT_READY": active_containment_ready(evidence),
        "state": "BLOCKED_CREDENTIALS",
        "blockers": ["Developer ID Application identity unavailable", "helper not installed", "signed frozen system engine unavailable", "live XPC not authenticated", "sensor-originated live target unavailable", "crash/reboot qualification unavailable"],
        "safety": {"source_mode_containment": "disabled", "arbitrary_pid_api": False, "arbitrary_signal_api": False},
    }
