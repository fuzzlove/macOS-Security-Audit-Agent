from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HEALTH_DEFAULTS = {
    "clickfix_guard_installed": False, "clickfix_guard_running": False,
    "clickfix_guard_signature_valid": False, "clickfix_guard_version": None,
    "event_tap_active": False, "event_tap_mode": "INACTIVE", "last_shortcut_event_utc": None,
    "input_monitoring_granted": False, "accessibility_granted": False,
    "clipboard_access_state": "CLIPBOARD_ACCESS_UNKNOWN", "clipboard_classifier_loaded": False,
    "classifier_signature_valid": False, "classifier_version": None, "xpc_authenticated": False,
    "xpc_listener_ready": False,
    "last_heartbeat_utc": None, "event_queue_drops": 0, "protect_mode_active": False,
    "clipboard_quarantine_enabled": False, "endpoint_security_correlation_available": False,
    "development_demo": False, "native_journal_integrity_valid": False,
}


def sensor_path() -> Path:
    return Path(os.environ.get("MSAA_CLICKFIX_AGENT", str(Path.home() / "Library/Application Support/MacAuditAgent/ClickFixGuard/MSAAClickFixGuardAgent.app")))


def doctor(stored: dict[str, Any]) -> dict[str, Any]:
    status = dict(HEALTH_DEFAULTS); status.update(stored)
    path = sensor_path(); status["clickfix_guard_installed"] = path.exists()
    if path.exists():
        result = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)], capture_output=True, text=True, timeout=5, check=False)
        status["clickfix_guard_signature_valid"] = result.returncode == 0
        if result.returncode:
            status["signature_error"] = "CFX001_SENSOR_NOT_INSTALLED" if not path.exists() else "signature validation failed"
    heartbeat = status.get("last_heartbeat_utc")
    if heartbeat:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(str(heartbeat).replace("Z", "+00:00"))).total_seconds()
            status["clickfix_guard_running"] = age <= 30
        except ValueError:
            status["clickfix_guard_running"] = False
    monitoring_active = all((status["clickfix_guard_installed"], status["clickfix_guard_running"], status["clickfix_guard_signature_valid"], status["event_tap_active"], status["input_monitoring_granted"], status["classifier_signature_valid"]))
    xpc_integration_active = bool(status["xpc_listener_ready"] and status["xpc_authenticated"])
    journal_integration_active = bool(status["development_demo"] and status["native_journal_integrity_valid"])
    integration_active = xpc_integration_active or journal_integration_active
    status["integration_mode"] = "authenticated_xpc" if xpc_integration_active else "verified_native_journal" if journal_integration_active else "unavailable"
    status["monitoring_active"] = monitoring_active
    status["integration_active"] = integration_active
    status["fully_active"] = monitoring_active and integration_active
    status["proof_of_concept_ready"] = bool(
        status["clickfix_guard_installed"]
        and status["clickfix_guard_running"]
        and status["clickfix_guard_signature_valid"]
        and status["classifier_signature_valid"]
        and integration_active
    )
    status["error_codes"] = []
    status["blocked_by"] = []
    if not status["clickfix_guard_installed"]:
        # Permission, classifier, and XPC readiness cannot be evaluated before
        # the native process exists. Reporting every downstream predicate made
        # CFX012 look like a separate listener defect when CFX001 was the root.
        status["error_codes"].append("CFX001_SENSOR_NOT_INSTALLED")
        status["blocked_by"].append("clickfix_guard_not_installed")
        status["recommended_action"] = "Build, sign, and install MSAAClickFixGuardAgent.app for the logged-in user."
    elif not status["clickfix_guard_running"]:
        status["error_codes"].append("CFX002_SENSOR_NOT_RUNNING")
        status["blocked_by"].append("clickfix_guard_not_running")
        status["recommended_action"] = "Repair and start com.macos-security-audit-agent.clickfix-guard in the current gui/<uid> domain."
    else:
        if not status["input_monitoring_granted"]:
            status["error_codes"].append("CFX003_INPUT_MONITORING_DENIED")
        if not status["classifier_signature_valid"]:
            status["error_codes"].append("CFX009_CLASSIFIER_SIGNATURE_INVALID")
        if not status["xpc_listener_ready"] and not journal_integration_active:
            status["error_codes"].append("CFX012_XPC_LISTENER_NOT_READY")
        elif not status["xpc_authenticated"] and not journal_integration_active:
            status["error_codes"].append("CFX012_XPC_CLIENT_NOT_CONNECTED")
        if not status["input_monitoring_granted"]:
            status["recommended_action"] = (
                "Enable MSAAClickFixGuardAgent in Privacy & Security > Input Monitoring. "
                "The running agent will retry its event tap automatically."
            )
        elif not integration_active:
            status["recommended_action"] = "Verify the authenticated XPC client or the integrity-checked native journal bridge."
        else:
            status["recommended_action"] = "ClickFix Guard proof-of-concept monitoring is active."
    return status
