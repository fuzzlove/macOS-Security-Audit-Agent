from __future__ import annotations

from typing import Any

SIGNED_INSTALL_COMMAND = "sudo .venv/bin/python launcher.py --install-protection-services"
DEVELOPMENT_INSTALL_COMMAND = SIGNED_INSTALL_COMMAND + " --developer-mode --allow-unsigned-development-runtime"


def development_sensor_install_guide(status: dict[str, Any] | None = None) -> dict[str, Any]:
    """Describe the truthful observer installation path without claiming ES parity."""
    status = status or {}
    daemon = status.get("system_daemon", {}) if isinstance(status, dict) else {}
    return {
        "schema_version": "1.0",
        "component": "MSAA System Monitor — Development Ransomware Observer",
        "architecture": "hosted_in_existing_system_monitor_launchdaemon",
        "launchd_label": "com.mac-audit-agent.monitor",
        "installation_required": not bool(daemon.get("installed")),
        "running": bool(daemon.get("running")),
        "administrator_approval_required": True,
        "gui_runs_as_root": False,
        "password_collected_by_msaa": False,
        "terminal_automation": "MSAA opens Terminal with a fixed, visible command; sudo performs authentication and MSAA never receives the password.",
        "signed_or_packaged_command": SIGNED_INSTALL_COMMAND,
        "unsigned_source_development_command": DEVELOPMENT_INSTALL_COMMAND,
        "development_exception_warning": "Use the unsigned source command only on an authorized isolated development Mac. It does not create an Apple signature or Endpoint Security entitlement.",
        "steps": [
            "Review the installation plan in MSAA.",
            "Select Open Terminal for Administrator Install, review the visible command, and continue only on an authorized Mac.",
            "If Terminal cannot be opened, copy the exact command shown by MSAA. macOS sudo prompts the administrator; MSAA does not receive the password.",
            "Reopen MSAA as the normal logged-in user.",
            "Select Verify Sensor Installation and confirm the daemon heartbeat and observer state.",
            "Grant Full Disk Access only to the exact reviewed installed component if protected research folders require it, then verify again.",
        ],
        "installed_capabilities": ["Boot-persistent System Monitor LaunchDaemon", "Delayed metadata-only observation of bounded Desktop, Documents, and Downloads roots", "Local multi-window ransomware correlation", "Local YARA scanning when a validated backend and rules are available", "Durable local event logging and user notifier integration"],
        "not_provided_without_apple_entitlement": ["Pre-execution Endpoint Security authorization", "Complete process attribution or guaranteed event delivery", "Endpoint Security event subscriptions", "Production containment parity", "Apple signing, notarization, approval, or entitlement"],
        "expected_production_state": "DEGRADED_OBSERVATION_ONLY until the entitled signed Endpoint Security sensor is installed and connected",
    }


__all__ = ["DEVELOPMENT_INSTALL_COMMAND", "SIGNED_INSTALL_COMMAND", "development_sensor_install_guide"]
