from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    description: str
    severity: str
    confidence_default: str
    source_detector: str
    false_positive_hints: list[str]
    verification_steps: list[str]
    mitre_mapping: str = ""
    enabled_by_default: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rule(
    rule_id: str,
    name: str,
    category: str,
    description: str,
    severity: str,
    confidence_default: str,
    source_detector: str,
    false_positive_hints: list[str],
    verification_steps: list[str],
    mitre_mapping: str = "",
    enabled_by_default: bool = True,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        category=category,
        description=description,
        severity=severity,
        confidence_default=confidence_default,
        source_detector=source_detector,
        false_positive_hints=false_positive_hints,
        verification_steps=verification_steps,
        mitre_mapping=mitre_mapping,
        enabled_by_default=enabled_by_default,
    )


RULES: dict[str, Rule] = {
    "launchdaemon_added": _rule(
        "launchdaemon_added",
        "LaunchDaemon Added",
        "persistence",
        "A new system LaunchDaemon plist appeared under /Library/LaunchDaemons.",
        "critical",
        "high",
        "persistence_monitor",
        ["software install or update", "managed endpoint tooling", "approved service deployment"],
        ["Inspect the plist target, owner, code signature, and package receipt.", "Confirm whether the change matches an approved installation or admin action."],
        "T1543.001",
    ),
    "launchagent_added": _rule(
        "launchagent_added",
        "LaunchAgent Added",
        "persistence",
        "A new LaunchAgent plist appeared in a LaunchAgents directory.",
        "high",
        "high",
        "persistence_monitor",
        ["user-installed app", "helper app update", "managed software deployment"],
        ["Inspect the plist target and ownership.", "Confirm whether the agent belongs to an approved application."],
        "T1543.001",
    ),
    "launchagent_removed": _rule(
        "launchagent_removed",
        "LaunchAgent Removed",
        "persistence",
        "A LaunchAgent plist disappeared from a LaunchAgents directory.",
        "high",
        "high",
        "persistence_monitor",
        ["admin cleanup", "software uninstall", "managed policy update"],
        ["Confirm whether the removal was intentional.", "Review the deleted plist path and nearby admin activity."],
        "T1543.001",
    ),
    "persistence_item_created_high_risk": _rule(
        "persistence_item_created_high_risk",
        "Login Item Added",
        "persistence",
        "A new login item was added for the current user.",
        "critical",
        "high",
        "persistence_monitor",
        ["user preference change", "new app install", "managed profile"],
        ["Inspect the login item name and source application.", "Confirm whether the item was added intentionally."],
        "T1547.015",
    ),
    "login_item_added": _rule(
        "login_item_added",
        "Login Item Added",
        "persistence",
        "A login item was added for the current user.",
        "critical",
        "high",
        "persistence_monitor",
        ["normal app onboarding", "managed profile", "user preference change"],
        ["Confirm whether the login item was intentionally added.", "Review the source application and user context."],
        "T1547.015",
    ),
    "launchdaemon_removed": _rule(
        "launchdaemon_removed",
        "LaunchDaemon Removed",
        "persistence",
        "A system LaunchDaemon plist disappeared from /Library/LaunchDaemons.",
        "critical",
        "high",
        "persistence_monitor",
        ["admin uninstall", "service update", "managed repair"],
        ["Confirm the service removal was intended.", "Review the plist path and recent admin actions."],
        "T1543.001",
    ),
    "admin_user_removed": _rule(
        "admin_user_removed",
        "Admin User Removed",
        "identity",
        "An administrative user was removed or lost admin status.",
        "high",
        "high",
        "baseline_drift",
        ["account lifecycle change", "managed deprovisioning", "directory sync"],
        ["Confirm whether the admin change was approved.", "Review nearby persistence and login activity."],
    ),
    "network_ip_assigned": _rule(
        "network_ip_assigned",
        "Network IP Assigned",
        "network",
        "An interface received a new IP address assignment.",
        "info",
        "high",
        "network_detector",
        ["expected DHCP lease renewal", "interface reconnect", "network switch change"],
        ["Confirm the interface, subnet, and gateway match the expected environment.", "Verify whether the change aligns with a known network transition."],
    ),
    "new_network_connection_detected": _rule(
        "new_network_connection_detected",
        "New Network Connection Detected",
        "network",
        "A new active network connection or interface transition was observed.",
        "high",
        "high",
        "network_detector",
        ["network reconnect", "interface reassignment", "expected VPN or dock change"],
        ["Confirm the new connection matches expected network activity.", "Review nearby session, device, and login events."],
    ),
    "new_outbound_connection_detected": _rule(
        "new_outbound_connection_detected",
        "New Outbound Connection Detected",
        "network",
        "A new outbound network path was observed.",
        "high",
        "high",
        "network_detector",
        ["VPN establishment", "dock reconnect", "expected interface change"],
        ["Confirm the outbound path matches expected host and network activity.", "Review nearby process and persistence events."],
    ),
    "new_inbound_connection_detected": _rule(
        "new_inbound_connection_detected",
        "New Inbound Connection Detected",
        "network",
        "A new inbound network path or exposure was observed.",
        "critical",
        "high",
        "network_detector",
        ["managed service exposure", "remote administration", "expected listener"],
        ["Confirm the inbound exposure is intentional.", "Review local listeners, sharing services, and remote access settings."],
    ),
    "new_gateway_detected": _rule(
        "new_gateway_detected",
        "New Gateway Detected",
        "network",
        "The default gateway changed.",
        "high",
        "high",
        "network_detector",
        ["normal network transition", "VPN route change", "dock reconnect"],
        ["Confirm the gateway change matches the expected environment.", "Review nearby network and session events."],
    ),
    "new_dns_server_detected": _rule(
        "new_dns_server_detected",
        "New DNS Server Detected",
        "network",
        "The active DNS server changed.",
        "high",
        "high",
        "network_detector",
        ["DHCP lease renewal", "VPN profile refresh", "network switching"],
        ["Confirm the DNS change matches expected network behavior.", "Review router, VPN, and profile changes."],
    ),
    "vpn_disconnected": _rule(
        "vpn_disconnected",
        "VPN Disconnected",
        "network",
        "A previously present VPN interface disappeared.",
        "medium",
        "high",
        "network_detector",
        ["VPN sleep", "profile disconnect", "user disconnect"],
        ["Confirm the VPN disconnect was expected.", "Review surrounding network and session events."],
    ),
    "vpn_connected": _rule(
        "vpn_connected",
        "VPN Connected",
        "network",
        "A VPN interface appeared or changed state.",
        "info",
        "high",
        "network_detector",
        ["user initiated VPN", "managed always-on VPN", "profile refresh"],
        ["Confirm the profile and endpoint are expected.", "Check whether the VPN change matches user activity or policy."],
    ),
    "remote_login_enabled": _rule(
        "remote_login_enabled",
        "Remote Login Enabled",
        "persistence",
        "Remote login was enabled on the local host.",
        "critical",
        "high",
        "sharing_detector",
        ["managed remote admin", "temporary support access", "approved maintenance window"],
        ["Confirm the remote login setting is approved.", "Review nearby admin and persistence changes."],
        "T1021",
    ),
    "screen_sharing_enabled": _rule(
        "screen_sharing_enabled",
        "Screen Sharing Enabled",
        "persistence",
        "Screen sharing or remote desktop access was enabled.",
        "critical",
        "high",
        "sharing_detector",
        ["support session", "managed remote assistance", "approved remote admin"],
        ["Confirm the remote sharing setting is approved.", "Review nearby admin and persistence changes."],
        "T1021",
    ),
    "display_sleep": _rule(
        "display_sleep",
        "Display Sleep",
        "session",
        "The display transitioned to sleep.",
        "info",
        "high",
        "session_monitor",
        ["normal idle sleep", "user-initiated sleep", "power management"],
        ["Confirm the transition matches expected user or power-state activity."],
    ),
    "display_wake": _rule(
        "display_wake",
        "Display Wake",
        "session",
        "The display transitioned back to awake.",
        "info",
        "high",
        "session_monitor",
        ["normal wake", "lid open", "user returning to desk"],
        ["Confirm the wake matches expected user activity."],
    ),
    "screen_locked": _rule(
        "screen_locked",
        "Screen Locked",
        "session",
        "The local GUI session transitioned to a locked state.",
        "info",
        "high",
        "session_monitor",
        ["user locked the screen", "idle lock policy", "sleep transition"],
        ["Confirm the lock transition matches expected workstation activity."],
    ),
    "screen_unlocked": _rule(
        "screen_unlocked",
        "Screen Unlocked",
        "session",
        "The local GUI session transitioned to an unlocked state.",
        "high",
        "high",
        "session_monitor",
        ["authorized user unlocked the screen", "login transition", "wake transition"],
        ["Confirm the unlock transition matches an authorized user action.", "Review nearby input and device events."],
    ),
    "possible_lid_opened": _rule(
        "possible_lid_opened",
        "Possible Lid Opened",
        "session",
        "A lid-open transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid open", "dock reconnect", "power state transition"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "lid_opened": _rule(
        "lid_opened",
        "Lid Opened",
        "session",
        "A lid-open transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid open", "dock reconnect", "power state transition"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "possible_lid_closed": _rule(
        "possible_lid_closed",
        "Possible Lid Closed",
        "session",
        "A lid-closed transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid close", "closing a laptop", "travel or docking"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "lid_closed": _rule(
        "lid_closed",
        "Lid Closed",
        "session",
        "A lid-closed transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid close", "closing a laptop", "travel or docking"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "usb_device_connected": _rule(
        "usb_device_connected",
        "USB Connected",
        "hardware",
        "A previously seen USB device was recognized again.",
        "info",
        "high",
        "hardware_detector",
        ["physical reconnect", "dock reconnect", "USB hub topology change"],
        ["Confirm the USB device is expected.", "Compare vendor, product, serial, and port identity."],
    ),
    "usb_device_removed": _rule(
        "usb_device_removed",
        "USB Removed",
        "hardware",
        "A previously seen USB device is no longer present.",
        "medium",
        "high",
        "hardware_detector",
        ["expected disconnect", "dock removal", "device powered off"],
        ["Confirm the removed USB device was expected.", "Compare the device identity against baseline."],
    ),
    "usb_inventory_changed": _rule(
        "usb_inventory_changed",
        "USB Inventory Changed",
        "hardware",
        "The USB device inventory changed.",
        "medium",
        "high",
        "hardware_detector",
        ["dock churn", "port reconnect", "expected accessory change"],
        ["Review which USB devices were added or removed.", "Correlate the change with nearby session events."],
    ),
    "new_usb_device_detected": _rule(
        "new_usb_device_detected",
        "New USB Device Detected",
        "hardware",
        "A new USB device identity was observed.",
        "critical",
        "high",
        "hardware_detector",
        ["new accessory", "dock replacement", "vendor firmware update"],
        ["Inspect the vendor, product, serial, and attachment location.", "Confirm whether the device is approved for use."],
    ),
    "bluetooth_device_connected": _rule(
        "bluetooth_device_connected",
        "Bluetooth Device Connected",
        "hardware",
        "A connected Bluetooth device identity appeared in the local I/O registry.",
        "medium",
        "high",
        "hardware_detector",
        ["approved keyboard, mouse, trackpad, headset, or accessory", "device reconnect after sleep", "dock or controller restart"],
        ["Confirm the connected device name and address are expected.", "Review nearby session events if the connection was unexpected."],
    ),
    "bluetooth_device_disconnected": _rule(
        "bluetooth_device_disconnected",
        "Bluetooth Device Disconnected",
        "hardware",
        "A previously seen Bluetooth device disconnected.",
        "medium",
        "high",
        "hardware_detector",
        ["device sleep", "expected disconnect", "accessory power loss"],
        ["Confirm the disconnected Bluetooth device was expected.", "Review nearby session events if the disconnect was unexpected."],
    ),
    "bluetooth_inventory_changed": _rule(
        "bluetooth_inventory_changed",
        "Bluetooth Inventory Changed",
        "hardware",
        "The Bluetooth device inventory changed.",
        "medium",
        "high",
        "hardware_detector",
        ["expected reconnect", "accessory sleep", "device reboot"],
        ["Review which Bluetooth devices were added or removed.", "Correlate with nearby power and session events."],
    ),
    "unknown_hid_device_detected": _rule(
        "unknown_hid_device_detected",
        "Unknown HID Device Detected",
        "hardware",
        "An input device could not be confidently identified.",
        "high",
        "medium",
        "hardware_detector",
        ["broken descriptor", "dock passthrough", "accessibility device"],
        ["Confirm the attached input device is expected.", "Compare the device identity and attachment timing against baseline."],
    ),
    "system_moisture_detected": _rule(
        "system_moisture_detected",
        "Moisture Detected",
        "hardware",
        "A moisture or liquid warning marker was observed.",
        "critical",
        "high",
        "hardware_detector",
        ["transient sensor text", "environmental warning", "hardware log artifact"],
        ["Disconnect external power and inspect the affected port or device.", "Confirm whether the signal was a real hardware warning."],
    ),
    "suspicious_process_observed": _rule(
        "suspicious_process_observed",
        "Suspicious Process Observed",
        "execution",
        "A process started from an unexpected path or with a risky command line.",
        "high",
        "medium",
        "process_detector",
        ["developer tooling", "temporary build output", "admin maintenance task"],
        ["Inspect the binary path, parent process, and code signature.", "Compare the process hash against baseline if available."],
        "T1059",
    ),
    "capture_capable_process_observed": _rule(
        "capture_capable_process_observed",
        "Capture-Capable Process Observed",
        "privacy",
        "A capture-capable application was observed running.",
        "medium",
        "low",
        "privacy_monitor",
        ["normal conferencing app", "screen recording app", "browser media helper"],
        ["Confirm the app is expected to be open.", "Correlate with nearby session or privacy events."],
    ),
    "capture_capable_process_closed": _rule(
        "capture_capable_process_closed",
        "Capture-Capable Process Closed",
        "privacy",
        "A previously observed capture-capable application process stopped.",
        "info",
        "medium",
        "privacy_monitor",
        ["video call ended", "browser tab closed", "capture application quit"],
        ["Confirm the process stop matches expected user activity.", "Review nearby camera and microphone indicator events."],
    ),
    "camera_activity_suspected": _rule(
        "camera_activity_suspected",
        "Camera-Related Activity Observed",
        "privacy",
        "A camera helper process or camera-related correlation was observed without a confirmed public camera-active API signal.",
        "medium",
        "medium",
        "privacy_monitor",
        ["camera helper startup", "video application launch", "browser media initialization"],
        ["Confirm whether camera-capable software was intentionally started.", "Correlate with confirmed camera-active API signals."],
    ),
    "microphone_activity_suspected": _rule(
        "microphone_activity_suspected",
        "Microphone-Capable Activity Observed",
        "privacy",
        "A microphone-capable process was observed without a confirmed audio-capture signal.",
        "medium",
        "low",
        "privacy_monitor",
        ["video call application", "browser media process", "audio application startup"],
        ["Confirm the application was expected to run.", "Review nearby session and privacy events."],
    ),
    "camera_activity_confirmed": _rule(
        "camera_activity_confirmed",
        "Camera Activity Confirmed",
        "privacy",
        "A camera-active signal was observed from public APIs.",
        "high",
        "high",
        "privacy_monitor",
        ["legitimate video call", "camera test", "photobooth session"],
        ["Confirm whether camera use is expected.", "Check the active application and nearby events."],
    ),
    "camera_activity_stopped": _rule(
        "camera_activity_stopped",
        "Camera Activity Stopped",
        "privacy",
        "A previously observed public camera-active API signal stopped.",
        "info",
        "high",
        "privacy_monitor",
        ["video call ended", "camera app closed", "camera preview stopped"],
        ["Confirm the camera stop transition matches the expected application lifecycle.", "Review nearby camera start and process events."],
    ),
    "input_activity_resumed_after_idle": _rule(
        "input_activity_resumed_after_idle",
        "Input Resumed After Idle",
        "session",
        "Keyboard, mouse, and trackpad input resumed after a sustained idle period.",
        "medium",
        "high",
        "session_monitor",
        ["user returned to desk", "remote session wake", "touchpad movement while docked"],
        ["Confirm the input resume was expected.", "Review surrounding session and display events."],
    ),
    "input_activity_idle_started": _rule(
        "input_activity_idle_started",
        "Input Idle Transition",
        "session",
        "Aggregate keyboard, mouse, and trackpad input remained idle past the configured threshold.",
        "info",
        "high",
        "session_monitor",
        ["user stepped away", "display left unattended", "workstation locked separately"],
        ["Correlate the idle transition with expected workstation use.", "Review subsequent input-resume and session events."],
    ),
    "idle_resume_detected": _rule(
        "idle_resume_detected",
        "Idle Resume Detected",
        "session",
        "Input resumed after a sustained idle period.",
        "medium",
        "high",
        "session_monitor",
        ["user returned to desk", "remote session wake", "touchpad movement while docked"],
        ["Confirm the resumed activity was expected.", "Review surrounding session and display events."],
    ),
    "mouse_or_keyboard_activity_after_idle": _rule(
        "mouse_or_keyboard_activity_after_idle",
        "Mouse or Keyboard Activity After Idle",
        "session",
        "Mouse or keyboard activity resumed after a sustained idle period.",
        "medium",
        "high",
        "session_monitor",
        ["user returned to desk", "remote session wake", "touchpad movement while docked"],
        ["Confirm the resumed activity was expected.", "Review surrounding session and display events."],
    ),
    "alert_storm_detected": _rule(
        "alert_storm_detected",
        "Alert Storm Detected",
        "provenance",
        "Many alerts with the same shape appeared in a short window.",
        "high",
        "medium",
        "alert_storm_detector",
        ["benign noisy app", "broken detector", "automation or install churn"],
        ["Review the top event types and sources.", "Check whether the detector itself is noisy or the activity is expected."],
    ),
    "monitor_self_impact_warning": _rule(
        "monitor_self_impact_warning",
        "Monitor Self-Impact Warning",
        "monitoring",
        "The audit agent observed sustained resource pressure that it may be contributing to.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["temporary system load", "approved intensive scan", "large software installation or update"],
        [
            "Review the self-impact score and resource metrics.",
            "Allow the bounded polling backoff to reduce load.",
            "Pause intensive scans and inspect monitor logs if pressure persists.",
        ],
    ),
    "new_admin_user_detected": _rule(
        "new_admin_user_detected",
        "New Admin User Detected",
        "identity",
        "A new administrative user was observed.",
        "critical",
        "high",
        "baseline_drift",
        ["normal account creation", "managed user onboarding", "directory service sync"],
        ["Confirm the account owner and whether the admin grant was approved."],
    ),
    "heartbeat": _rule(
        "heartbeat",
        "Heartbeat",
        "monitoring",
        "Monitor heartbeat event.",
        "info",
        "high",
        "monitor",
        ["routine monitor activity"],
        ["No action needed unless the monitor is unhealthy."],
    ),
    "protected_monitor_tamper_detected": _rule(
        "protected_monitor_tamper_detected",
        "Protected Monitor Tamper Detected",
        "integrity",
        "A protected monitor plist, runtime path, or tracked runtime file changed from the installed manifest.",
        "critical",
        "high",
        "integrity_check",
        ["authorized admin repair", "expected monitor update", "package reinstall"],
        [
            "Compare the observed owner, mode, and hash values with the stored install manifest.",
            "Review recent admin activity and persistence changes before making modifications.",
            "Reinstall the protected monitor from a trusted copy if the change is expected to be malicious or accidental.",
        ],
        "T1562",
    ),
    "monitor_blindness_detected": _rule(
        "monitor_blindness_detected",
        "Monitor Blindness Detected",
        "monitoring",
        "The monitor lost visibility or another detector appears stale.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["temporary OS slowdown", "expected detector outage", "approved reboot"],
        ["Review which detector stopped reporting.", "Inspect the shared DB, heartbeat, and notifier state before acting."],
    ),
    "detector_stopped": _rule(
        "detector_stopped",
        "Detector Stopped",
        "monitoring",
        "A detector stopped reporting events.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["temporary restart", "maintenance", "expected detector pause"],
        ["Review the detector name and last event time.", "Confirm whether the detector stop is expected."],
    ),
    "heartbeat_stale": _rule(
        "heartbeat_stale",
        "Heartbeat Stale",
        "monitoring",
        "The monitor heartbeat age exceeded the expected window.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["brief system load", "paused scan", "sleep transition"],
        ["Confirm whether the monitor is still healthy.", "Review the heartbeat and shared DB write status."],
    ),
    "db_not_updating": _rule(
        "db_not_updating",
        "Database Not Updating",
        "monitoring",
        "The shared monitor database stopped receiving updates.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["temporary lock contention", "expected maintenance", "DB migration"],
        ["Confirm that the shared database is writable.", "Review lock contention and recent errors."],
    ),
    "notifier_not_running": _rule(
        "notifier_not_running",
        "Notifier Not Running",
        "monitoring",
        "The user notifier stopped running.",
        "critical",
        "high",
        "self_impact_watchdog",
        ["logout", "user session restart", "expected notifier restart"],
        ["Confirm whether the notifier should still be active.", "Review the launch agent or daemon status."],
    ),
    "unexpected_process_execution": _rule(
        "unexpected_process_execution",
        "Unexpected Process Execution",
        "execution",
        "A process executed unexpectedly based on available local context.",
        "critical",
        "high",
        "process_detector",
        ["admin maintenance", "developer tooling", "approved software install"],
        ["Review the process path, parent, and signature.", "Preserve nearby evidence before cleanup."],
        "T1059",
    ),
    "execution_evidence_detected": _rule(
        "execution_evidence_detected",
        "Execution Evidence Detected",
        "execution",
        "Execution evidence was observed for a process or command line.",
        "critical",
        "high",
        "process_detector",
        ["approved admin activity", "installer activity", "known automation"],
        ["Review the evidence summary, parent process, and launch context.", "Preserve logs and review the timeline."],
        "T1059",
    ),
    "unsigned_process_from_temp": _rule(
        "unsigned_process_from_temp",
        "Unsigned Process From Temp",
        "execution",
        "An unsigned process executed from a temporary path.",
        "critical",
        "high",
        "process_detector",
        ["build artifact", "installer extraction", "temporary test binary"],
        ["Preserve the binary hash and path.", "Review parent process and recent downloads."],
        "T1036",
    ),
    "temp_process_with_network_connection": _rule(
        "temp_process_with_network_connection",
        "Temp Process With Network Connection",
        "execution",
        "A process from a temporary path also made a network connection.",
        "critical",
        "high",
        "process_detector",
        ["installer helper", "test harness", "known temporary build tool"],
        ["Review the process path, network endpoint, and parent process.", "Preserve the timeline before cleanup."],
        "T1071",
    ),
    "browser_spawned_shell": _rule(
        "browser_spawned_shell",
        "Browser Spawned Shell",
        "execution",
        "A browser process launched a shell.",
        "critical",
        "high",
        "process_detector",
        ["developer console", "automation", "safe local testing"],
        ["Review the browser tab, process tree, and command line.", "Preserve logs and timeline evidence."],
        "T1059",
    ),
    "mail_spawned_shell": _rule(
        "mail_spawned_shell",
        "Mail Spawned Shell",
        "execution",
        "A mail application launched a shell.",
        "critical",
        "high",
        "process_detector",
        ["mail plugin", "help desk tooling", "automation"],
        ["Review the mail process tree and attached helpers.", "Preserve the event timeline before remediation."],
        "T1059",
    ),
    "preview_spawned_shell": _rule(
        "preview_spawned_shell",
        "Preview Spawned Shell",
        "execution",
        "Preview launched a shell.",
        "critical",
        "high",
        "process_detector",
        ["PDF tooling", "automation", "trusted document workflow"],
        ["Review the document path, parent process, and command line.", "Preserve the evidence trail."],
        "T1059",
    ),
    "office_app_spawned_shell": _rule(
        "office_app_spawned_shell",
        "Office App Spawned Shell",
        "execution",
        "An office application launched a shell.",
        "critical",
        "high",
        "process_detector",
        ["macros", "trusted automation", "document workflow"],
        ["Review the document and macro context.", "Preserve the timeline before responding."],
        "T1059",
    ),
    "low_trust_binary_executed": _rule(
        "low_trust_binary_executed",
        "Low Trust Binary Executed",
        "execution",
        "A low-trust or low-reputation binary executed.",
        "critical",
        "high",
        "process_detector",
        ["admin install", "developer build", "known-good internal tool"],
        ["Review the signing status, path, and parent process.", "Preserve logs and file hashes."],
        "T1204",
    ),
    "port_open_no_process_owner": _rule(
        "port_open_no_process_owner",
        "Open Port With No Owner",
        "network",
        "A local listening port was observed without a clear process owner.",
        "critical",
        "high",
        "network_detector",
        ["system service race", "transient port scan artifact", "known background helper"],
        ["Review the listener details and process ownership.", "Preserve the network timeline before cleanup."],
        "T1046",
    ),
    "new_listener_detected": _rule(
        "new_listener_detected",
        "New Listener Detected",
        "network",
        "A new local listener appeared.",
        "critical",
        "high",
        "network_detector",
        ["expected service start", "developer server", "approved admin workflow"],
        ["Review the listener port, process, and binding address.", "Preserve the event timeline before remediation."],
        "T1046",
    ),
    "reverse_shell_pattern_detected": _rule(
        "reverse_shell_pattern_detected",
        "Reverse Shell Pattern Detected",
        "network",
        "A reverse-shell-like pattern was observed.",
        "critical",
        "high",
        "network_detector",
        ["training lab", "safe red team simulation", "approved test harness"],
        ["Review the endpoint, process, and timeline.", "Preserve the evidence before any cleanup."],
        "T1021",
    ),
    "persistence_after_execution": _rule(
        "persistence_after_execution",
        "Persistence After Execution",
        "persistence",
        "Persistence appeared shortly after execution evidence.",
        "critical",
        "high",
        "persistence_monitor",
        ["installer flow", "managed update", "admin deployment"],
        ["Review the parent process and persistence target.", "Preserve the timeline and related file hashes."],
        "T1547",
    ),
    "admin_change_after_execution": _rule(
        "admin_change_after_execution",
        "Admin Change After Execution",
        "identity",
        "Administrative privileges changed shortly after execution evidence.",
        "critical",
        "high",
        "baseline_drift",
        ["managed user lifecycle", "IT admin change", "directory sync"],
        ["Confirm whether the change was approved.", "Review the execution and account change timeline."],
    ),
}

EVENT_TYPE_ALIASES: dict[str, str] = {
    "screen_wake": "display_wake",
    "screen_sleep": "display_sleep",
    "system_wake": "display_wake",
    "system_sleep": "display_sleep",
    "display_state_changed": "display_wake",
    "session_locked": "screen_locked",
    "session_unlocked": "screen_unlocked",
    "possible_lid_opened": "lid_opened",
    "possible_lid_closed": "lid_closed",
    "clamshell_state_changed": "lid_opened",
    "clamshell_open": "lid_opened",
    "clamshell_opened": "lid_opened",
    "clamshell_closed": "lid_closed",
    "clamshell_close": "lid_closed",
    "new_ip_assigned": "network_ip_assigned",
    "mouse_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "keyboard_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "trackpad_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "mouse_or_keyboard_activity": "mouse_or_keyboard_activity_after_idle",
    "input_activity_after_idle": "mouse_or_keyboard_activity_after_idle",
    "hid_activity_after_idle": "mouse_or_keyboard_activity_after_idle",
    "usb_inventory_changed": "usb_device_connected",
    "current_usb_device_inventory_changed": "usb_inventory_changed",
    "usb_reconnect_detected": "usb_device_connected",
    "usb_device_reconnected": "usb_device_connected",
    "bluetooth_inventory_changed": "bluetooth_device_connected",
    "bluetooth_activity_started": "bluetooth_device_connected",
    "bluetooth_activity_stopped": "bluetooth_device_disconnected",
    "capture_process_observed": "capture_capable_process_observed",
    "hidden_localhost_port_detected": "localhost_hidden_port_detected",
}


def registered_rule_ids() -> list[str]:
    return sorted(RULES)


def validate_rule_registry() -> list[str]:
    problems: list[str] = []
    for rule_id, rule in RULES.items():
        if not rule.rule_id:
            problems.append(f"rule {rule_id} is missing rule_id")
        if rule.rule_id != rule_id:
            problems.append(f"rule key {rule_id} does not match rule_id {rule.rule_id}")
        if not rule.name:
            problems.append(f"rule {rule_id} is missing name")
        if not rule.description:
            problems.append(f"rule {rule_id} is missing description")
        if not rule.source_detector:
            problems.append(f"rule {rule_id} is missing source_detector")
    return problems


def rule_registry_summary() -> dict[str, object]:
    validation_problems = validate_rule_registry()
    return {
        "rule_count": len(RULES),
        "enabled_rule_count": sum(1 for rule in RULES.values() if rule.enabled_by_default),
        "validation_problem_count": len(validation_problems),
        "validation_problems": validation_problems,
        "registered_rule_ids": registered_rule_ids(),
    }


def rule_for_event(event_type: str) -> Rule:
    canonical = canonical_event_type(event_type)
    return RULES.get(
        canonical,
        _rule(
            canonical or "unknown",
            canonical.replace("_", " ").title() if canonical else "Unknown Event",
            "provenance",
            "No explicit rule mapping exists for this event type.",
            "low",
            "low",
            "unknown_detector",
            ["limited context", "legacy event payload", "rule registry incomplete"],
            ["Inspect the detector and surrounding events.", "Add or update a rule mapping before relying on the popup."],
            enabled_by_default=False,
        ),
    )


def canonical_event_type(event_type: str) -> str:
    seen = set()
    current = str(event_type or "").strip()
    while current and current not in seen:
        seen.add(current)
        next_value = EVENT_TYPE_ALIASES.get(current, current)
        if next_value == current:
            break
        current = next_value
    return current


def rule_for_finding(category: str, title: str, evidence: str = "", command_used: str = "") -> Rule:
    normalized = f"{category} {title} {evidence} {command_used}".lower()
    if "launchdaemon" in normalized:
        return RULES["launchdaemon_added"]
    if "launchagent" in normalized:
        return RULES["launchagent_added"]
    if "login item" in normalized:
        return RULES["persistence_item_created_high_risk"]
    if "port" in normalized:
        return _rule(
            "localhost_hidden_port_detected",
            "Hidden Localhost Port",
            "network",
            "A localhost-bound listening port was observed.",
            "critical",
            "high",
            "network_detector",
            ["developer service", "debug server", "local proxy"],
            ["Inspect the listening process and confirm whether the port should be open."],
        )
    if "process" in normalized or "execution" in normalized:
        return RULES["suspicious_process_observed"]
    if "history" in normalized:
        return _rule(
            "shell_history_pattern",
            "Shell History Pattern",
            "process",
            "A shell history pattern matched a risky command line.",
            "medium",
            "low",
            "history_detector",
            ["legitimate admin work", "training commands", "documentation snippets"],
            ["Review the surrounding history entries and confirm the command intent."],
        )
    return _rule(
        re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_") or "finding_rule",
        title,
        category,
        "A finding was created from scan evidence.",
        str("high" if category.lower() in {"baseline comparison", "persistence"} else "medium"),
        "medium",
        "scan_collector",
        ["benign maintenance", "software updates", "approved administrative activity"],
        ["Inspect the source artifact.", "Compare the item against baseline and surrounding events."],
    )


def sanitize_signal_text(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(authorization=)([^\s&]+(?:\s+[^\s&]+)?)", r"\1[redacted]", text)
    text = re.sub(r"(?i)(token|cookie|password)=([^\s&]+)", r"\1=[redacted]", text)
    text = re.sub(r"(?i)(bearer\s+)[^\s&]+", r"\1[redacted]", text)
    return text


def evidence_hash(*parts: Any) -> str:
    material = json.dumps([sanitize_signal_text(str(part)) for part in parts], sort_keys=True)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalized_signal(*parts: Any) -> str:
    return sanitize_signal_text(" | ".join(str(part) for part in parts if str(part)))


def correlation_id_for(*parts: Any, timestamp: str | None = None, bucket_seconds: int = 300) -> str:
    bucket = ""
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            epoch = int(dt.timestamp())
            bucket = str(epoch - (epoch % max(1, bucket_seconds)))
        except ValueError:
            bucket = timestamp[:16]
    material = normalized_signal(*parts, bucket)
    return f"corr-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"
