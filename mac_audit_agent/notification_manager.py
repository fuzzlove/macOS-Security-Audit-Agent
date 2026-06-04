from __future__ import annotations

import subprocess
import json
import hashlib
import os
import re
import time
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mac_audit_agent.models import AlertDeliveryRecord, BackgroundMonitorEvent, EventAlertTrace, NotificationCapabilities, utc_now_iso
from mac_audit_agent.rules import canonical_event_type, rule_for_event


SEVERITY_LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OSASCRIPT_BIN = "/usr/bin/osascript"
NOTIFICATION_PATH_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
IMPORTANT_EVENT_TYPES = {
    "camera_activity_suspected",
    "camera_activity_confirmed",
    "camera_activity_stopped",
    "microphone_activity_suspected",
    "capture_capable_process_observed",
    "screen_locked",
    "screen_unlocked",
    "session_locked",
    "session_unlocked",
    "display_sleep",
    "display_wake",
    "possible_lid_closed",
    "possible_lid_opened",
    "lid_closed",
    "lid_opened",
    "screen_sharing_enabled",
    "system_moisture_detected",
    "new_usb_device_detected",
    "bluetooth_device_connected",
    "input_activity_idle_started",
    "remote_login_enabled",
    "suspicious_process_observed",
    "persistence_item_created",
    "localhost_hidden_port_detected",
    "new_admin_user_detected",
    "packet_capture_started",
    "packet_capture_completed",
    "major_security_event",
    "monitor_self_impact_warning",
    "monitor_self_test",
}
ACTIVITY_OVERLAY_EVENT_TYPES = {
    "bluetooth_device_connected",
    "camera_activity_confirmed",
    "camera_activity_stopped",
    "camera_activity_suspected",
    "capture_capable_process_observed",
    "capture_capable_process_closed",
    "display_sleep",
    "display_wake",
    "input_activity_idle_started",
    "input_activity_resumed_after_idle",
    "microphone_activity_suspected",
    "network_ip_assigned",
    "new_usb_device_detected",
    "possible_lid_closed",
    "possible_lid_opened",
    "protected_monitor_tamper_detected",
    "screen_locked",
    "screen_unlocked",
    "system_moisture_detected",
    "usb_device_connected",
    "vpn_connected",
}
MANDATORY_VISIBLE_ALERT_EVENT_TYPES = {
    "lid_opened",
    "lid_closed",
    "possible_lid_opened",
    "possible_lid_closed",
    "display_wake",
    "display_sleep",
    "screen_unlocked",
    "screen_locked",
    "user_logged_in",
    "user_logged_out",
    "idle_resume_detected",
    "mouse_activity_detected",
    "keyboard_activity_detected",
    "trackpad_activity_detected",
    "mouse_or_keyboard_activity_after_idle",
    "input_activity_after_idle",
    "hid_activity_after_idle",
    "usb_device_connected",
    "usb_device_removed",
    "new_usb_device_detected",
    "usb_inventory_changed",
    "bluetooth_device_connected",
    "bluetooth_device_disconnected",
    "bluetooth_activity_started",
    "bluetooth_activity_stopped",
    "bluetooth_inventory_changed",
    "unknown_hid_device_detected",
    "new_network_connection_detected",
    "new_outbound_connection_detected",
    "new_inbound_connection_detected",
    "new_ip_assigned",
    "network_ip_assigned",
    "vpn_connected",
    "vpn_disconnected",
    "new_gateway_detected",
    "new_dns_server_detected",
    "remote_login_enabled",
    "screen_sharing_enabled",
    "new_admin_user_detected",
    "admin_user_removed",
    "launchagent_added",
    "launchagent_removed",
    "launchdaemon_added",
    "launchdaemon_removed",
    "login_item_added",
    "persistence_item_created_high_risk",
    "protected_monitor_tamper_detected",
    "unexpected_process_execution",
    "execution_evidence_detected",
    "suspicious_process_observed",
    "unsigned_process_from_temp",
    "temp_process_with_network_connection",
    "browser_spawned_shell",
    "mail_spawned_shell",
    "preview_spawned_shell",
    "office_app_spawned_shell",
    "low_trust_binary_executed",
    "hidden_localhost_port_detected",
    "localhost_hidden_port_detected",
    "port_open_no_process_owner",
    "new_listener_detected",
    "reverse_shell_pattern_detected",
    "persistence_after_execution",
    "admin_change_after_execution",
    "alert_storm_detected",
    "monitor_blindness_detected",
    "detector_stopped",
    "heartbeat_stale",
    "db_not_updating",
    "notifier_not_running",
}
MANDATORY_IDLE_NOTICE_EVENT_TYPES = {
    "idle_resume_detected",
    "mouse_or_keyboard_activity_after_idle",
    "input_activity_after_idle",
    "hid_activity_after_idle",
    "input_activity_resumed_after_idle",
}
MANDATORY_CRITICAL_EVENT_TYPES = {
    "new_admin_user_detected",
    "admin_user_removed",
    "launchagent_added",
    "launchagent_removed",
    "launchdaemon_added",
    "launchdaemon_removed",
    "login_item_added",
    "persistence_item_created_high_risk",
    "protected_monitor_tamper_detected",
    "unexpected_process_execution",
    "execution_evidence_detected",
    "suspicious_process_observed",
    "unsigned_process_from_temp",
    "temp_process_with_network_connection",
    "browser_spawned_shell",
    "mail_spawned_shell",
    "preview_spawned_shell",
    "office_app_spawned_shell",
    "low_trust_binary_executed",
    "hidden_localhost_port_detected",
    "localhost_hidden_port_detected",
    "port_open_no_process_owner",
    "new_listener_detected",
    "reverse_shell_pattern_detected",
    "persistence_after_execution",
    "admin_change_after_execution",
    "alert_storm_detected",
    "monitor_blindness_detected",
    "detector_stopped",
    "heartbeat_stale",
    "db_not_updating",
    "notifier_not_running",
}
CRITICAL_POPUP_ALLOWLIST = {
    "camera_activity_confirmed",
    "camera_activity_started",
    "camera_activity_stopped",
    "possible_lid_opened",
    "possible_lid_closed",
    "user_logged_in",
    "user_logged_out",
    "screen_unlocked",
    "new_admin_user_detected",
    "admin_user_removed",
    "launchdaemon_added",
    "launchdaemon_removed",
    "launchagent_added_high_risk",
    "launchagent_removed_high_risk",
    "persistence_item_created_high_risk",
    "alert_storm_detected",
    "hidden_localhost_port_detected",
    "suspicious_root_process_observed",
    "remote_login_enabled",
    "screen_sharing_enabled",
    "system_moisture_detected",
    "protected_monitor_tamper_detected",
    "monitor_self_impact_warning",
}
BROWSER_HELPER_KEYWORDS = {
    "operahelper",
    "operahelper(renderer)",
    "operahelpergpu",
    "chromehelper",
    "safariwebcontent",
    "firefoxhelper",
    "videocaptureservice",
    "audioservice",
    "video_capture",
    "audio service",
}
DEFAULT_EVENT_PREFERENCES: dict[str, dict[str, object]] = {
    "new_admin_user_detected": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "startup_daemon_added_system": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "persistence_item_created_high_risk": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "hidden_localhost_port_detected": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "suspicious_root_process_observed": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "launchdaemon_added": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "alert_storm_detected": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "camera_activity_confirmed": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "camera_activity_stopped": {"enabled": True, "severity": "info", "notify": False, "cooldown_seconds": 60, "notification_mode": "none"},
    "camera_activity_suspected": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 120, "notification_mode": "notification"},
    "microphone_activity_suspected": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 120, "notification_mode": "none"},
    "possible_lid_opened": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "possible_lid_closed": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "lid_opened": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "lid_closed": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "user_logged_in": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "user_logged_out": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "screen_unlocked": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "screen_locked": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "remote_login_enabled": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "screen_sharing_enabled": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "suspicious_process_observed": {"enabled": True, "severity": "high", "notify": False, "cooldown_seconds": 600, "notification_mode": "none"},
    "launchagent_added": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "persistence_item_created": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "major_security_event": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "display_sleep": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 120, "notification_mode": "notification"},
    "display_wake": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 120, "notification_mode": "notification"},
    "screen_locked_state_changed": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "file_sharing_enabled": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "input_activity_resumed_after_idle": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "idle_resume_detected": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "mouse_or_keyboard_activity_after_idle": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "input_activity_after_idle": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "hid_activity_after_idle": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "input_activity_idle_started": {"enabled": True, "severity": "info", "notify": False, "cooldown_seconds": 120, "notification_mode": "none"},
    "usb_device_connected": {"enabled": True, "severity": "info", "notify": True, "cooldown_seconds": 0, "notification_mode": "notification"},
    "usb_device_removed": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 60, "notification_mode": "notification"},
    "new_usb_device_detected": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 0, "notification_mode": "both"},
    "system_moisture_detected": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "both"},
    "protected_monitor_tamper_detected": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 300, "notification_mode": "dialog"},
    "monitor_self_impact_warning": {"enabled": True, "severity": "critical", "notify": True, "cooldown_seconds": 900, "notification_mode": "dialog"},
    "network_ip_assigned": {"enabled": True, "severity": "info", "notify": True, "cooldown_seconds": 0, "notification_mode": "notification"},
    "vpn_connected": {"enabled": True, "severity": "info", "notify": True, "cooldown_seconds": 0, "notification_mode": "notification"},
    "bluetooth_device_connected": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 60, "notification_mode": "notification"},
    "bluetooth_device_disconnected": {"enabled": True, "severity": "medium", "notify": True, "cooldown_seconds": 60, "notification_mode": "notification"},
    "unknown_hid_device_detected": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 60, "notification_mode": "dialog"},
    "capture_capable_process_observed": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 120, "notification_mode": "none"},
    "capture_capable_process_closed": {"enabled": True, "severity": "info", "notify": False, "cooldown_seconds": 60, "notification_mode": "none"},
}
FALLBACK_MONITOR_LOG = Path.home() / "Library" / "Logs" / "MacAuditAgent" / "monitor.log"
CFAA_ACK_RETRY_SECONDS = 300
CFAA_ACK_ASID_RE = re.compile(r"\basid\s*=\s*(\d+)\b")
CFAA_ACK_MESSAGE = (
    "Authorized use reminder\n\n"
    "Use this computer and its connected systems only with authorization. "
    "Unauthorized access or exceeding authorized access may violate policy and applicable law, "
    "including the Computer Fraud and Abuse Act, 18 U.S.C. 1030.\n\n"
    "Security indicators are logged locally. This reminder is not legal advice or a legal determination.\n\n"
    "Click Acknowledge to confirm that you understand this authorized-use reminder."
)
OVERLAY_SEVERITIES = {"info", "medium", "high", "critical"}
OVERLAY_STATE_PATH = Path.home() / ".mac_audit_agent" / "state" / "security_overlay.json"
OVERLAY_PID_PATH = Path.home() / ".mac_audit_agent" / "state" / "security_overlay.pid"
NOTIFICATION_READINESS_PATH = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "notification_readiness.json"

VISIBLE_ALERT_CATEGORY_EVENT_TYPES = {
    "physical_session": {
        "camera_activity_suspected",
        "camera_activity_confirmed",
        "camera_activity_stopped",
        "microphone_activity_suspected",
        "lid_opened",
        "lid_closed",
        "possible_lid_opened",
        "possible_lid_closed",
        "display_wake",
        "display_sleep",
        "screen_unlocked",
        "screen_locked",
        "user_logged_in",
        "user_logged_out",
        "input_activity_resumed_after_idle",
        "input_activity_idle_started",
        "idle_resume_detected",
        "mouse_or_keyboard_activity_after_idle",
        "input_activity_after_idle",
        "hid_activity_after_idle",
    },
    "device": {
        "usb_device_connected",
        "usb_device_removed",
        "new_usb_device_detected",
        "usb_inventory_changed",
        "current_usb_device_inventory_changed",
        "bluetooth_device_connected",
        "bluetooth_device_disconnected",
        "bluetooth_activity_started",
        "bluetooth_activity_stopped",
        "bluetooth_inventory_changed",
        "unknown_hid_device_detected",
    },
    "network": {
        "new_network_connection_detected",
        "network_ip_assigned",
        "new_ip_assigned",
        "new_outbound_connection_detected",
        "new_inbound_connection_detected",
        "vpn_connected",
        "vpn_disconnected",
        "new_gateway_detected",
        "new_dns_server_detected",
    },
    "persistence_admin": {
        "new_admin_user_detected",
        "admin_user_removed",
        "launchagent_added",
        "launchagent_removed",
        "launchdaemon_added",
        "launchdaemon_removed",
        "login_item_added",
        "persistence_item_created_high_risk",
        "protected_monitor_tamper_detected",
        "screen_sharing_enabled",
        "remote_login_enabled",
    },
    "advisory": {
        "apple_security_forecast_elevated",
        "apple_security_forecast_urgent",
        "cve_forecast_level_increased",
    },
}


@dataclass(frozen=True)
class AlertDecision:
    show: bool
    style: str
    reason: str
    cooldown_remaining: int
    persistent: bool


def applescript_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _run_osascript_command(command: list[str], runner=None, timeout: int = 5):
    runner = runner or subprocess.run
    try:
        return runner(command, timeout=timeout, capture_output=True, text=True, env=NOTIFICATION_PATH_ENV)
    except subprocess.TimeoutExpired as exc:
        stdout = getattr(exc, "stdout", "") or ""
        stderr = getattr(exc, "stderr", "") or f"command timed out after {timeout} seconds"
        return subprocess.CompletedProcess(command, 124, stdout=stdout, stderr=stderr)
    except Exception as exc:  # noqa: BLE001
        return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(exc))


def send_notification(title, subtitle, message, sound="Glass", runner=None):
    script = (
        f'display notification "{applescript_escape(message)}" '
        f'with title "{applescript_escape(title)}" '
        f'subtitle "{applescript_escape(subtitle)}"'
    )
    if sound:
        script += f' sound name "{applescript_escape(sound)}"'
    return _run_osascript_command([OSASCRIPT_BIN, "-e", script], runner=runner, timeout=5)


def send_alert_dialog(title, message, runner=None):
    script = (
        f'display dialog "{applescript_escape(message)}" '
        f'with title "{applescript_escape(title)}" '
        'buttons {"Acknowledge"} default button "Acknowledge" with icon caution'
    )
    return _run_osascript_command([OSASCRIPT_BIN, "-e", script], runner=runner, timeout=5)


class NotificationManager:
    def __init__(self, db, runner=None, popen_factory=None) -> None:
        self.db = db
        self.runner = runner or subprocess.run
        self.popen_factory = popen_factory or subprocess.Popen
        self._cfaa_ack_process = None
        self._cfaa_ack_session_key = ""
        self._cfaa_ack_last_attempt = 0.0
        try:
            self.refresh_notification_capabilities()
        except Exception:
            pass

    def settings(self) -> dict[str, object]:
        raw_preferences = self.db.get_background_monitor_state("event_preferences_json", "")
        try:
            event_preferences = json.loads(raw_preferences) if raw_preferences else {}
        except json.JSONDecodeError:
            event_preferences = {}
        return {
            "notify_all_events": self.db.get_background_monitor_state("notify_all_events", "0") == "1",
            "notify_important_events": self.db.get_background_monitor_state("notify_important_events", "1") != "0",
            "notify_min_severity": self.db.get_background_monitor_state("notify_min_severity", "info"),
            "notification_sound": self.db.get_background_monitor_state("notification_sound", "Glass"),
            "duplicate_rate_limit_seconds": max(0, int(self.db.get_background_monitor_state("duplicate_rate_limit_seconds", "10") or "10")),
            "high_priority_alert_style": self.db.get_background_monitor_state("high_priority_alert_style", "notification"),
            "notification_mode": self.db.get_background_monitor_state("notification_mode", "notification"),
            "popup_only_severe_events": self.db.get_background_monitor_state("popup_only_severe_events", "1") != "0",
            "browser_capture_process_popup": self.db.get_background_monitor_state("browser_capture_process_popup", "0") == "1",
            "show_visible_alerts": self.db.get_background_monitor_state("show_visible_alerts", "1") != "0",
            "show_physical_session_alerts": self.db.get_background_monitor_state("show_physical_session_alerts", "1") != "0",
            "show_usb_bluetooth_alerts": self.db.get_background_monitor_state("show_usb_bluetooth_alerts", "1") != "0",
            "show_network_change_alerts": self.db.get_background_monitor_state("show_network_change_alerts", "1") != "0",
            "show_admin_persistence_alerts": self.db.get_background_monitor_state("show_admin_persistence_alerts", "1") != "0",
            "show_apple_forecast_alerts": self.db.get_background_monitor_state("show_apple_forecast_alerts", "1") != "0",
            "idle_activity_warning_minutes": int(self.db.get_background_monitor_state("idle_activity_warning_minutes", "2") or "2"),
            "cfaa_idle_warning_enabled": self.db.get_background_monitor_state("cfaa_idle_warning_enabled", "1") != "0",
            "cooldown_seconds_per_category": int(self.db.get_background_monitor_state("cooldown_seconds_per_category", "600") or "600"),
            "event_preferences": event_preferences,
        }

    def update_settings(
        self,
        *,
        notify_all_events: bool,
        notify_important_events: bool,
        notify_min_severity: str,
        notification_sound: str,
        duplicate_rate_limit_seconds: int,
        high_priority_alert_style: str = "notification",
        notification_mode: str = "notification",
        popup_only_severe_events: bool = True,
        browser_capture_process_popup: bool = False,
        show_visible_alerts: bool = True,
        show_physical_session_alerts: bool = True,
        show_usb_bluetooth_alerts: bool = True,
        show_network_change_alerts: bool = True,
        show_admin_persistence_alerts: bool = True,
        show_apple_forecast_alerts: bool = True,
        idle_activity_warning_minutes: int = 2,
        cfaa_idle_warning_enabled: bool = True,
        cooldown_seconds_per_category: int = 600,
    ) -> None:
        self.db.set_background_monitor_state("notify_all_events", "1" if notify_all_events else "0")
        self.db.set_background_monitor_state("notify_important_events", "1" if notify_important_events else "0")
        self.db.set_background_monitor_state("notify_min_severity", notify_min_severity)
        self.db.set_background_monitor_state("notification_sound", notification_sound or "Glass")
        self.db.set_background_monitor_state("duplicate_rate_limit_seconds", str(max(0, duplicate_rate_limit_seconds)))
        self.db.set_background_monitor_state("high_priority_alert_style", high_priority_alert_style or "notification")
        self.db.set_background_monitor_state("notification_mode", notification_mode or "notification")
        self.db.set_background_monitor_state("popup_only_severe_events", "1" if popup_only_severe_events else "0")
        self.db.set_background_monitor_state("browser_capture_process_popup", "1" if browser_capture_process_popup else "0")
        self.db.set_background_monitor_state("show_visible_alerts", "1" if show_visible_alerts else "0")
        self.db.set_background_monitor_state("show_physical_session_alerts", "1" if show_physical_session_alerts else "0")
        self.db.set_background_monitor_state("show_usb_bluetooth_alerts", "1" if show_usb_bluetooth_alerts else "0")
        self.db.set_background_monitor_state("show_network_change_alerts", "1" if show_network_change_alerts else "0")
        self.db.set_background_monitor_state("show_admin_persistence_alerts", "1" if show_admin_persistence_alerts else "0")
        self.db.set_background_monitor_state("show_apple_forecast_alerts", "1" if show_apple_forecast_alerts else "0")
        self.db.set_background_monitor_state("idle_activity_warning_minutes", str(max(1, idle_activity_warning_minutes)))
        self.db.set_background_monitor_state("cfaa_idle_warning_enabled", "1" if cfaa_idle_warning_enabled else "0")
        self.db.set_background_monitor_state("cooldown_seconds_per_category", str(max(0, cooldown_seconds_per_category)))

    def event_preferences(self) -> dict[str, dict[str, object]]:
        settings = self.settings()
        merged = {key: dict(value) for key, value in DEFAULT_EVENT_PREFERENCES.items()}
        for key, value in dict(settings["event_preferences"]).items():
            if isinstance(value, dict):
                merged[key] = {**merged.get(key, {}), **value}
        return merged

    def update_event_preferences(self, preferences: dict[str, dict[str, object]]) -> None:
        self.db.set_background_monitor_state("event_preferences_json", json.dumps(preferences, sort_keys=True))

    def preference_for(self, event_type: str) -> dict[str, object]:
        event_type = self._canonical_event_type(event_type)
        preferences = self.event_preferences()
        default_cooldown = {"critical": 300, "high": 600, "medium": 0, "low": 0, "info": 0}
        preference = dict(preferences.get(event_type, {}))
        mandatory = self._is_mandatory_visible_event(event_type)
        if mandatory:
            preference.setdefault("severity", "critical" if event_type in {self._canonical_event_type(item) for item in MANDATORY_CRITICAL_EVENT_TYPES} else "high")
            preference.setdefault("notify", True)
            preference.setdefault("notification_mode", "dialog" if str(preference.get("severity", "high")) in {"high", "critical"} else "notification")
            preference.setdefault("cooldown_seconds", 0 if event_type in {"usb_device_connected", "new_usb_device_detected", "bluetooth_device_connected", "network_ip_assigned", "vpn_connected"} else 600)
        severity = str(preference.get("severity", "low"))
        preference.setdefault("enabled", True)
        preference.setdefault("notify", event_type in CRITICAL_POPUP_ALLOWLIST)
        preference.setdefault("cooldown_seconds", default_cooldown.get(severity, 1800))
        default_mode = "dialog" if severity in {"critical", "high"} and event_type in CRITICAL_POPUP_ALLOWLIST else ("notification" if severity == "medium" else "none")
        preference.setdefault("notification_mode", preference.get("alert_style", default_mode))
        return preference

    def status(self) -> str:
        capabilities = self.capabilities()
        if capabilities.overlay_available or capabilities.applescript_dialog_available:
            if capabilities.notification_center_available:
                return "security alerts ready (overlay, dialog, notification center)"
            return "security alerts ready (overlay/dialog; notification center optional)"
        return "security alerts unavailable"

    def _notification_readiness_path(self) -> Path:
        return NOTIFICATION_READINESS_PATH

    def capabilities(self) -> NotificationCapabilities:
        osascript_exists = Path(OSASCRIPT_BIN).exists()
        overlay_available = Path(__file__).resolve().parent.joinpath("security_overlay.py").exists()
        applescript_dialog_available = osascript_exists
        notification_center_available = osascript_exists
        last = self.db.latest_notification_capabilities() if hasattr(self.db, "latest_notification_capabilities") else None
        return NotificationCapabilities(
            overlay_available=overlay_available,
            applescript_dialog_available=applescript_dialog_available,
            notification_center_available=notification_center_available,
            osascript_exists=osascript_exists,
            last_test_time=getattr(last, "last_test_time", ""),
            last_test_result=getattr(last, "last_test_result", ""),
        )

    def _write_notification_readiness(self, payload: dict[str, object]) -> None:
        path = self._notification_readiness_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            return

    def refresh_notification_capabilities(self) -> NotificationCapabilities:
        capabilities = self.capabilities()
        capabilities.last_test_time = utc_now_iso()
        capabilities.last_test_result = "capability-detection"
        try:
            self.db.record_notification_capabilities(capabilities)
        except Exception:
            pass
        self._write_notification_readiness(
            {
                "updated_at": capabilities.last_test_time,
                "capabilities": capabilities.to_dict(),
                "last_test_result": capabilities.last_test_result,
                "security_alerting_ready": bool(capabilities.overlay_available or capabilities.applescript_dialog_available),
            }
        )
        self.db.set_background_monitor_state("notification_capabilities_json", json.dumps(capabilities.to_dict(), sort_keys=True))
        self.db.set_background_monitor_state("notification_readiness_json", json.dumps({
            "updated_at": capabilities.last_test_time,
            "capabilities": capabilities.to_dict(),
            "last_test_result": capabilities.last_test_result,
            "security_alerting_ready": bool(capabilities.overlay_available or capabilities.applescript_dialog_available),
        }, sort_keys=True))
        self.db.set_background_monitor_state("notification_status", self.status())
        return capabilities

    def _run_dialog_readiness_attempt(self, title: str, message: str) -> object:
        script = (
            f'display dialog "{applescript_escape(message)}" '
            f'with title "{applescript_escape(title)}" '
            'buttons {"Acknowledge"} default button "Acknowledge" giving up after 1 with icon caution'
        )
        return _run_osascript_command([OSASCRIPT_BIN, "-e", script], runner=self.runner, timeout=5)

    def readiness_check(self) -> dict[str, object]:
        capabilities = self.refresh_notification_capabilities()
        now = utc_now_iso()
        overlay_event = BackgroundMonitorEvent(
            event_id=f"notification-readiness-overlay-{now}",
            timestamp=now,
            event_type="protected_monitor_tamper_detected",
            severity="critical",
            source="notification_readiness",
            evidence="Overlay readiness test.",
            confidence="high",
            simulated=True,
            notification_sent=False,
            rule_id="notification_readiness",
            rule_name="Notification Readiness",
            trigger_rule_id="notification_readiness",
            trigger_rule_name="Notification Readiness",
        )
        overlay_ok = False
        overlay_error = ""
        try:
            overlay_ok = bool(self.show_visible_security_alert(overlay_event, reason="notification_readiness", force=True))
        except Exception as exc:
            overlay_error = str(exc)
        dialog_result = self._run_dialog_readiness_attempt(
            "Mac Audit Agent - Notification Readiness",
            "Dialog readiness test. You may close this automatically dismissing alert.",
        ) if capabilities.applescript_dialog_available else None
        dialog_ok = bool(dialog_result is not None and getattr(dialog_result, "returncode", 1) == 0)
        dialog_error = ""
        if dialog_result is not None and getattr(dialog_result, "returncode", 1) != 0:
            dialog_error = (getattr(dialog_result, "stderr", "") or getattr(dialog_result, "stdout", "") or "dialog failed").strip()
        notification_result = send_notification(
            "Mac Audit Agent",
            "Notification Readiness",
            "Notification Center readiness test.",
            sound="",
            runner=self.runner,
        ) if capabilities.notification_center_available else None
        notification_ok = bool(notification_result is not None and getattr(notification_result, "returncode", 1) == 0)
        notification_error = ""
        if notification_result is not None and getattr(notification_result, "returncode", 1) != 0:
            notification_error = (getattr(notification_result, "stderr", "") or getattr(notification_result, "stdout", "") or "notification failed").strip()
        overall_pass = bool(overlay_ok or dialog_ok)
        result = {
            "updated_at": now,
            "overlay": {
                "available": bool(capabilities.overlay_available),
                "attempted": True,
                "success": overlay_ok,
                "error": overlay_error,
            },
            "dialog": {
                "available": bool(capabilities.applescript_dialog_available),
                "attempted": bool(dialog_result is not None),
                "success": dialog_ok,
                "error": dialog_error,
            },
            "notification_center": {
                "available": bool(capabilities.notification_center_available),
                "attempted": bool(notification_result is not None),
                "success": notification_ok,
                "error": notification_error,
            },
            "overall_status": "PASS" if overall_pass else "FAIL",
            "reason": "Security alerts remain operational." if overall_pass else "All alert mechanisms failed.",
            "security_alerting_ready": overall_pass,
            "notification_center_optional": True,
            "last_test_time": now,
            "last_test_result": "PASS" if overall_pass else "FAIL",
            "capabilities": capabilities.to_dict(),
        }
        self.db.set_background_monitor_state("notification_readiness_json", json.dumps(result, sort_keys=True))
        self.db.set_background_monitor_state("notification_status", self.status())
        self.db.set_background_monitor_state("last_notification_error", notification_error)
        self.db.set_background_monitor_state("last_dialog_error", dialog_error)
        self.db.set_background_monitor_state("last_overlay_error", overlay_error)
        self.db.set_background_monitor_state("last_test_time", now)
        self.db.set_background_monitor_state("last_test_result", result["last_test_result"])
        self.db.set_background_monitor_state("notification_capabilities_json", json.dumps(capabilities.to_dict(), sort_keys=True))
        try:
            self.db.record_notification_capabilities(
                NotificationCapabilities(
                    overlay_available=bool(capabilities.overlay_available),
                    applescript_dialog_available=bool(capabilities.applescript_dialog_available),
                    notification_center_available=bool(capabilities.notification_center_available),
                    osascript_exists=bool(capabilities.osascript_exists),
                    last_test_time=now,
                    last_test_result=result["last_test_result"],
                )
            )
        except Exception:
            pass
        self._write_notification_readiness(result)
        return result

    def start_cfaa_login_acknowledgment(self) -> bool:
        self.poll_cfaa_login_acknowledgment()
        session_key = self._gui_session_key()
        if not session_key:
            self.db.set_background_monitor_state("cfaa_acknowledgment_status", "unavailable: GUI session identifier not found")
            return False
        if self.db.get_background_monitor_state("cfaa_acknowledged_session", "") == session_key:
            self.db.set_background_monitor_state("cfaa_acknowledgment_status", f"acknowledged for {session_key}")
            return False
        if self._cfaa_ack_process is not None and self._cfaa_ack_process.poll() is None:
            return False
        if self._cfaa_ack_last_attempt and time.monotonic() - self._cfaa_ack_last_attempt < CFAA_ACK_RETRY_SECONDS:
            return False
        script = (
            f'display dialog "{applescript_escape(CFAA_ACK_MESSAGE)}" '
            f'with title "{applescript_escape("Mac Audit Agent - Authorized Use Acknowledgment")}" '
            'buttons {"Acknowledge"} default button "Acknowledge" with icon caution'
        )
        self._cfaa_ack_session_key = session_key
        self._cfaa_ack_last_attempt = time.monotonic()
        self._cfaa_ack_process = self.popen_factory(
            [OSASCRIPT_BIN, "-e", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=NOTIFICATION_PATH_ENV,
        )
        self.db.set_background_monitor_state("cfaa_acknowledgment_status", f"pending for {session_key}")
        return True

    def poll_cfaa_login_acknowledgment(self) -> bool:
        if self._cfaa_ack_process is None:
            return False
        returncode = self._cfaa_ack_process.poll()
        if returncode is None:
            return False
        session_key = self._cfaa_ack_session_key
        self._cfaa_ack_process = None
        if returncode == 0 and session_key:
            self.db.set_background_monitor_state("cfaa_acknowledged_session", session_key)
            self.db.set_background_monitor_state("cfaa_acknowledged_at", datetime.now().astimezone().isoformat())
            self.db.set_background_monitor_state("cfaa_acknowledgment_status", f"acknowledged for {session_key}")
            return True
        self.db.set_background_monitor_state("cfaa_acknowledgment_status", f"not acknowledged for {session_key or 'unknown session'}")
        return False

    def _gui_session_key(self) -> str:
        result = _run_osascript_command(
            ["/bin/launchctl", "print", f"gui/{os.getuid()}"],
            runner=self.runner,
            timeout=5,
        )
        if getattr(result, "returncode", 1) != 0:
            return ""
        match = CFAA_ACK_ASID_RE.search(getattr(result, "stdout", "") or "")
        return f"gui/{os.getuid()}:asid/{match.group(1)}" if match else ""

    def should_notify(self, event: BackgroundMonitorEvent, *, force: bool = False) -> bool:
        decision = self.evaluate_notification_decision(event, force=force)
        return decision["notify"] and decision["decision"] == "sent"

    def _normalize_match_text(self, value: str) -> str:
        return "".join(ch for ch in value.lower() if ch.isalnum())

    def _canonical_event_type(self, event: BackgroundMonitorEvent | str) -> str:
        value = event if isinstance(event, str) else event.event_type
        return canonical_event_type(value)

    def _is_mandatory_visible_event(self, event: BackgroundMonitorEvent | str) -> bool:
        event_type = self._canonical_event_type(event)
        return event_type in {self._canonical_event_type(item) for item in MANDATORY_VISIBLE_ALERT_EVENT_TYPES}

    def _is_idle_notice_event(self, event: BackgroundMonitorEvent | str) -> bool:
        event_type = self._canonical_event_type(event)
        return event_type in {self._canonical_event_type(item) for item in MANDATORY_IDLE_NOTICE_EVENT_TYPES}

    def _event_alert_trace_id(self, event: BackgroundMonitorEvent) -> str:
        return f"trace-{event.event_id}"

    def _alert_signature(self, event: BackgroundMonitorEvent) -> str:
        parts = [
            self._canonical_event_type(event),
            getattr(event, "trigger_source", "") or getattr(event, "source", ""),
            getattr(event, "trigger_subsource", ""),
            getattr(event, "process_name", ""),
            str(getattr(event, "pid", "") or ""),
            getattr(event, "related_process", ""),
            str(getattr(event, "related_pid", "") or ""),
            getattr(event, "related_parent_pid", "") if getattr(event, "related_parent_pid", None) is not None else "",
            getattr(event, "related_path", ""),
            getattr(event, "related_user", ""),
            getattr(event, "related_network_endpoint", ""),
            getattr(event, "related_url", ""),
            getattr(event, "related_dom_selector", ""),
            getattr(event, "related_file_hash", ""),
            getattr(event, "previous_state", ""),
            getattr(event, "current_state", ""),
            getattr(event, "evidence_hash", ""),
            getattr(event, "correlation_id", ""),
            getattr(event, "raw_signal_summary", ""),
            getattr(event, "evidence", ""),
        ]
        signature = "\n".join(str(part or "") for part in parts)
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()

    def _update_event_alert_trace(self, event: BackgroundMonitorEvent, **updates: object) -> None:
        trace_id = self._event_alert_trace_id(event)
        payload = dict(updates)
        if "notifier_db_path" not in payload:
            payload["notifier_db_path"] = str(self.db.path)
        if "visible_alert_id" not in payload and getattr(event, "visible_alert_shown", False):
            payload["visible_alert_id"] = getattr(event, "visible_alert_id", "") or event.event_id
        try:
            self.db.update_event_alert_trace(trace_id, **payload)
        except Exception:
            return

    def _is_browser_helper_process(self, event: BackgroundMonitorEvent) -> bool:
        haystacks = [event.process_name or "", event.evidence or ""]
        normalized = [self._normalize_match_text(value) for value in haystacks]
        normalized_keywords = {self._normalize_match_text(keyword) for keyword in BROWSER_HELPER_KEYWORDS}
        return any(any(keyword and keyword in value for keyword in normalized_keywords) for value in normalized)

    def _alert_category_for_event(self, event_type: str) -> str:
        event_type = self._canonical_event_type(event_type)
        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["physical_session"]:
            return "physical_session"
        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["device"]:
            return "device"
        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["network"]:
            return "network"
        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["persistence_admin"]:
            return "persistence_admin"
        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["advisory"]:
            return "advisory"
        return "other"

    def _style_for_visible_alert(self, event: BackgroundMonitorEvent, *, category: str) -> str:
        event_type = self._canonical_event_type(event)
        if event_type in {self._canonical_event_type(item) for item in MANDATORY_CRITICAL_EVENT_TYPES}:
            return "critical_red"
        if event_type in {"lid_opened", "lid_closed", "screen_unlocked", "screen_locked", "user_logged_in", "user_logged_out", "mouse_or_keyboard_activity_after_idle", "idle_resume_detected", "input_activity_resumed_after_idle"}:
            return "high_orange"
        if event_type in {"apple_security_forecast_elevated", "cve_forecast_level_increased"}:
            return "high_orange" if event.severity in {"high", "critical"} else "neutral_grey"
        if category == "device" and event.severity in {"info", "medium"}:
            return "high_orange"
        if category == "device":
            return "high_orange" if event_type != "new_usb_device_detected" else "critical_red"
        if category in {"physical_session", "device", "network", "persistence_admin"} and event.severity in {"high", "critical"}:
            return "critical_red" if event.severity == "critical" else "high_orange"
        if category == "advisory":
            return "neutral_grey" if event.severity in {"info", "medium"} else "high_orange"
        if event.severity == "critical":
            return "critical_red"
        if event.severity == "high":
            return "high_orange"
        return "neutral_grey"

    def should_show_visible_alert(self, event: BackgroundMonitorEvent, preferences: dict[str, object] | None = None, *, force: bool = False) -> AlertDecision:
        settings = preferences if preferences is not None else self.settings()
        event_type = self._canonical_event_type(event)
        event.original_event_type = getattr(event, "original_event_type", "") or event.event_type
        event.normalized_event_type = event_type
        event.event_type = event_type
        if force:
            category = self._alert_category_for_event(event_type)
            style = self._style_for_visible_alert(event, category=category)
            return AlertDecision(True, style, "forced_visible_alert", 0, bool(event.severity == "critical"))
        if not bool(settings.get("show_visible_alerts", True)):
            return AlertDecision(False, "neutral_grey", "visible alerts disabled", 0, False)
        if not (getattr(event, "rule_id", "") or getattr(event, "trigger_rule_id", "")):
            return AlertDecision(False, "neutral_grey", "missing rule_id", 0, False)
        if self._is_browser_helper_process(event) and not settings.get("browser_capture_process_popup", False):
            return AlertDecision(False, "neutral_grey", "browser helper event is log-only by default", 0, False)

        category = self._alert_category_for_event(event_type)
        category_enabled = {
            "physical_session": bool(settings.get("show_physical_session_alerts", True)),
            "device": bool(settings.get("show_usb_bluetooth_alerts", True)),
            "network": bool(settings.get("show_network_change_alerts", True)),
            "persistence_admin": bool(settings.get("show_admin_persistence_alerts", True)),
            "advisory": bool(settings.get("show_apple_forecast_alerts", True)),
            "other": True,
        }.get(category, True)
        if not category_enabled:
            return AlertDecision(False, self._style_for_visible_alert(event, category=category), f"{category} alerts disabled", 0, False)

        if self._is_idle_notice_event(event_type):
            if not bool(settings.get("cfaa_idle_warning_enabled", True)):
                return AlertDecision(False, "high_orange", "idle activity warning disabled", 0, True)
            style = self._style_for_visible_alert(event, category=category)
            cooldown = 600
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, True)
                except ValueError:
                    pass
            return AlertDecision(True, style, "idle activity after inactivity", cooldown, True)

        if self._is_mandatory_visible_event(event_type):
            style = self._style_for_visible_alert(event, category=category)
            cooldown = int(settings.get("cooldown_seconds_per_category", 600) or 600)
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, event.severity == "critical")
                except ValueError:
                    pass
            return AlertDecision(True, style, f"{category} mandatory visible alert", cooldown, event.severity == "critical")

        if event.severity in {"high", "critical"}:
            style = self._style_for_visible_alert(event, category=category)
            cooldown = int(settings.get("cooldown_seconds_per_category", 600) or 600)
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, event.severity == "critical")
                except ValueError:
                    pass
            return AlertDecision(True, style, f"{category} high-priority alert", cooldown, event.severity == "critical")

        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["advisory"]:
            style = self._style_for_visible_alert(event, category=category)
            cooldown = int(settings.get("cooldown_seconds_per_category", 600) or 600)
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, False)
                except ValueError:
                    pass
            return AlertDecision(True, style, "advisory alert", cooldown, False)

        if category in {"physical_session", "device", "network", "persistence_admin"} and event.severity in {"info", "medium"}:
            style = self._style_for_visible_alert(event, category=category)
            cooldown = int(settings.get("cooldown_seconds_per_category", 600) or 600)
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, False)
                except ValueError:
                    pass
            return AlertDecision(True, style, f"{category} informational alert", cooldown, False)

        if event_type in VISIBLE_ALERT_CATEGORY_EVENT_TYPES["physical_session"] | VISIBLE_ALERT_CATEGORY_EVENT_TYPES["device"] | VISIBLE_ALERT_CATEGORY_EVENT_TYPES["network"] | VISIBLE_ALERT_CATEGORY_EVENT_TYPES["persistence_admin"]:
            style = self._style_for_visible_alert(event, category=category)
            cooldown = int(settings.get("cooldown_seconds_per_category", 600) or 600)
            last_timestamp = self.db.get_background_monitor_state(self._visible_alert_last_key(event), "")
            if last_timestamp:
                try:
                    remaining = max(0, cooldown - int((datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(last_timestamp)).total_seconds()))
                    if remaining > 0:
                        return AlertDecision(False, style, "within_cooldown", remaining, False)
                except ValueError:
                    pass
            return AlertDecision(True, style, f"{category} alert", cooldown, False)

        return AlertDecision(False, "neutral_grey", "log-only by default", 0, False)

    def should_popup(self, event: BackgroundMonitorEvent, preferences: dict[str, object] | None = None) -> tuple[bool, str]:
        settings = preferences if preferences is not None else self.settings()
        event.event_type = self._canonical_event_type(event)
        preference = self.preference_for(event.event_type)
        explicit_preferences = dict(settings.get("event_preferences", {}))
        explicit_preference = event.event_type in explicit_preferences
        severity = str(preference.get("severity", event.severity))
        event.severity = severity
        if not (getattr(event, "rule_id", "") or getattr(event, "trigger_rule_id", "")):
            return False, "missing rule_id"
        if not preference.get("enabled", True):
            return False, "disabled_by_user"
        if self._is_browser_helper_process(event) and not settings.get("browser_capture_process_popup", False):
            return False, "browser helper process logged silently"
        if event.event_type in DEFAULT_EVENT_PREFERENCES and preference.get("notify", False) and preference.get("notification_mode", "none") != "none":
            return True, "default event preference popup enabled"
        if explicit_preference and (
            not preference.get("notify", False) or str(preference.get("notification_mode", "none")) == "none"
        ):
            return False, "disabled_by_user"
        if explicit_preference and preference.get("notify", False) and preference.get("notification_mode", "none") != "none":
            return True, "user preference popup enabled"
        if event.event_type == "usb_device_connected" and preference.get("notify", False):
            return True, "USB recognition sound enabled"
        if event.event_type not in CRITICAL_POPUP_ALLOWLIST:
            return False, "event type is log-only by default"
        if severity not in {"high", "critical"}:
            return False, "severity below popup threshold"
        if settings.get("popup_only_severe_events", True):
            return True, "critical popup allowlist match"
        return bool(preference.get("notify", False)), "user popup policy override"

    def notify_findings_digest(self, findings: list[object]) -> tuple[bool, str]:
        normalized = [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in findings]
        if not normalized:
            return False, "no findings"
        severity_order = ["critical", "high", "medium", "low", "info"]
        counts = {severity: sum(1 for item in normalized if str(item.get("severity", "info")) == severity) for severity in severity_order}
        identifiers = sorted(
            str(cve_id)
            for item in normalized
            for cve_id in (item.get("cve_ids", []) or [item.get("title", "")])
            if cve_id
        )
        fingerprint = hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()
        if self.db.get_background_monitor_state("cfaa_findings_digest_fingerprint", "") == fingerprint:
            return False, "unchanged findings digest"
        summary = ", ".join(f"{count} {severity}" for severity, count in counts.items() if count) or f"{len(normalized)} findings"
        message = (
            f"Local review recorded {summary} indicators. Authorized use only. Activity is logged. "
            "Unauthorized access may violate policy and applicable law, including 18 U.S.C. 1030. "
            "This notice is not a legal determination."
        )
        sound = "Glass" if counts["critical"] or counts["high"] else ""
        result = send_notification("Mac Audit Agent", "Security Activity Summary", message, sound=sound, runner=self.runner)
        if getattr(result, "returncode", 1) != 0:
            detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "notification failed").strip()
            return False, detail
        self.db.set_background_monitor_state("cfaa_findings_digest_fingerprint", fingerprint)
        return True, ""

    def notify_cfaa_idle_reminder(self, event: BackgroundMonitorEvent) -> tuple[bool, str]:
        overlay_shown = bool(getattr(event, "visible_alert_shown", False))
        if overlay_shown:
            event.notification_sent = True
            event.notification_error = ""
            event.notification_returncode = 0
            event.notification_decision = "sent"
            event.notification_reason = "cfaa_idle_reminder"
            event.popup_allowed = True
            event.visible_alert_shown = True
            event.alert_style = "critical_red"
            self.db.set_background_monitor_state("cfaa_idle_reminder_at", datetime.now().astimezone().isoformat())
            self.db.set_background_monitor_state("notification_status", self.status())
            self._record_alert_delivery(
                event,
                overlay_attempted=True,
                overlay_success=True,
                dialog_attempted=False,
                dialog_success=False,
                notification_attempted=False,
                notification_success=False,
                delivery_method_used="overlay",
            )
            return True, ""

        command, result = self._run_dialog_attempt(CFAA_ACK_MESSAGE)
        self._log_attempt(event, str(event.severity), command, result, getattr(result, "returncode", 1) == 0)
        if getattr(result, "returncode", 1) == 0:
            event.notification_sent = True
            event.notification_error = ""
            event.notification_returncode = 0
            event.notification_decision = "sent"
            event.notification_reason = "cfaa_idle_reminder"
            event.popup_allowed = True
            event.visible_alert_shown = True
            event.alert_style = "critical_red"
            self.db.set_background_monitor_state("cfaa_idle_reminder_at", datetime.now().astimezone().isoformat())
            self.db.set_background_monitor_state("notification_status", self.status())
            self._record_alert_delivery(
                event,
                overlay_attempted=True,
                overlay_success=True,
                dialog_attempted=True,
                dialog_success=True,
                notification_attempted=False,
                notification_success=False,
                delivery_method_used="dialog",
            )
            return True, ""
        detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "notification failed").strip()
        event.notification_sent = False
        event.notification_error = detail
        event.notification_returncode = getattr(result, "returncode", None)
        self.db.set_background_monitor_state("notification_status", f"failed: {detail}")
        self.db.set_background_monitor_state("last_error", f"Notification failed for {event.event_type}: {detail}")
        self._write_fallback_log(f"notification error: type={event.event_type} detail={detail}")
        self._record_alert_delivery(
            event,
            overlay_attempted=overlay_shown,
            overlay_success=overlay_shown,
            dialog_attempted=True,
            dialog_success=False,
            notification_attempted=False,
            notification_success=False,
            delivery_method_used="overlay" if overlay_shown else "none",
        )
        return False, detail

    def evaluate_notification_decision(self, event: BackgroundMonitorEvent, *, force: bool = False) -> dict[str, object]:
        settings = self.settings()
        event.original_event_type = getattr(event, "original_event_type", "") or event.event_type
        event.event_type = self._canonical_event_type(event)
        event.normalized_event_type = event.event_type
        preference = self.preference_for(event.event_type)
        explicit_preference = event.event_type in dict(settings.get("event_preferences", {}))
        severity_before_policy = str(event.severity)
        effective_severity = str(preference.get("severity", event.severity))
        event.severity = effective_severity
        visible_alert = self.should_show_visible_alert(event, settings)
        event.visible_alert_shown = False
        event.alert_style = visible_alert.style
        event.cooldown_suppressed = visible_alert.reason == "within_cooldown"
        event.last_suppression_reason = visible_alert.reason
        if not rule_for_event(event.event_type).enabled_by_default:
            event.notification_decision = "no_policy_match"
            event.notification_reason = "no_policy_match"
            event.popup_allowed = False
            decision = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": effective_severity,
                "priority": effective_severity,
                "user_preference_loaded": explicit_preference,
                "notify": False,
                "alert_style": "neutral_grey",
                "cooldown_suppressed": False,
                "cooldown_remaining_seconds": 0,
                "decision": "no_policy_match",
                "reason": "no_policy_match",
                "command": "",
                "returncode": "",
                "stderr": "",
                "notification_sent": False,
                "popup_allowed": False,
                "visible_alert_shown": False,
                "alert_style": "neutral_grey",
                "cooldown_suppressed": False,
                "alert_suppressed_reason": "no_policy_match",
            }
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=False,
                alert_suppressed=True,
                alert_suppression_reason=decision["alert_suppressed_reason"],
            )
            self._write_decision(decision)
            return decision
        if event.cooldown_suppressed:
            try:
                current_count = int(self.db.get_background_monitor_state("suppressed_alert_count", "0") or "0")
            except ValueError:
                current_count = 0
            self.db.set_background_monitor_state("suppressed_alert_count", str(current_count + 1))
        if not (getattr(event, "rule_id", "") or getattr(event, "trigger_rule_id", "")):
            event.notification_decision = "invalid_incomplete"
            event.notification_reason = "missing_rule_id"
            event.popup_allowed = False
            decision = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": effective_severity,
                "priority": effective_severity,
                "user_preference_loaded": explicit_preference,
                "notify": False,
                "alert_style": preference.get("notification_mode", "none"),
                "cooldown_suppressed": False,
                "cooldown_remaining_seconds": 0,
                "decision": "invalid_incomplete",
                "reason": "missing_rule_id",
                "command": "",
                "returncode": "",
                "stderr": "",
                "notification_sent": False,
                "popup_allowed": False,
                "visible_alert_shown": False,
                "alert_style": "neutral_grey",
                "cooldown_suppressed": False,
                "alert_suppressed_reason": "missing_rule_id",
            }
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=not bool(visible_alert.show),
                alert_suppression_reason=decision["alert_suppressed_reason"],
            )
            self._write_decision(decision)
            return decision
        decision = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "severity": effective_severity,
            "priority": effective_severity,
            "user_preference_loaded": explicit_preference,
            "notify": False,
            "alert_style": preference.get("notification_mode", "none"),
            "cooldown_suppressed": False,
            "cooldown_remaining_seconds": 0,
            "decision": "log_only",
            "reason": "event type is log-only by default",
            "command": "",
            "returncode": "",
            "stderr": "",
            "notification_sent": False,
            "popup_allowed": False,
            "visible_alert_shown": bool(visible_alert.show),
            "alert_style": visible_alert.style,
            "cooldown_suppressed": False,
            "alert_suppressed_reason": "",
        }
        if not preference.get("enabled", True):
            event.notification_decision = "disabled_by_user"
            event.notification_reason = "event_disabled_by_preference"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            decision["decision"] = "disabled_by_user"
            decision["reason"] = "event_disabled_by_preference"
            decision["alert_suppressed_reason"] = "event_disabled_by_preference"
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=True,
                alert_suppression_reason=decision["alert_suppressed_reason"],
            )
            self._write_decision(decision)
            return decision
        if force:
            decision["notify"] = True
            decision["decision"] = "sent"
            decision["reason"] = "forced"
            event.notification_decision = "sent"
            event.notification_reason = "forced"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = True
            decision["popup_allowed"] = True
            decision["visible_alert_shown"] = True
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=True,
                alert_suppressed=False,
                alert_suppression_reason="",
            )
            self._write_decision(decision)
            return decision
        popup_allowed, reason = self.should_popup(event, settings)
        decision["popup_allowed"] = popup_allowed
        event.popup_allowed = popup_allowed
        notify_candidate = bool(visible_alert.show and self._is_mandatory_visible_event(event)) or (
            popup_allowed and bool(preference.get("notify", False) or explicit_preference or event.event_type in CRITICAL_POPUP_ALLOWLIST)
        )
        if not notify_candidate:
            event.notification_decision = "disabled_by_user" if reason == "disabled_by_user" else "log_only"
            event.notification_reason = reason
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            decision["decision"] = event.notification_decision
            decision["reason"] = reason
            decision["visible_alert_shown"] = bool(visible_alert.show)
            decision["alert_style"] = visible_alert.style
            decision["alert_suppressed_reason"] = reason
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=True,
                alert_suppression_reason=reason,
            )
            self._write_decision(decision)
            return decision
        min_level = SEVERITY_LEVELS.get(str(settings["notify_min_severity"]), 0)
        allow_default_info = event.event_type in DEFAULT_EVENT_PREFERENCES and preference.get("notify", False) and preference.get("notification_mode", "none") != "none"
        if SEVERITY_LEVELS.get(effective_severity, 0) < min_level and not allow_default_info:
            event.notification_decision = "log_only"
            event.notification_reason = "below_min_severity"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            decision["reason"] = "below_min_severity"
            decision["visible_alert_shown"] = bool(visible_alert.show)
            decision["alert_style"] = visible_alert.style
            decision["alert_suppressed_reason"] = "below_min_severity"
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=True,
                alert_suppression_reason="below_min_severity",
            )
            self._write_decision(decision)
            return decision
        decision["notify"] = True
        last_timestamp = self.db.get_background_monitor_state(self._last_key(event), "")
        if not last_timestamp:
            event.notification_decision = "sent"
            event.notification_reason = "first_severe_event"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = True
            decision["decision"] = "sent"
            decision["reason"] = "first_severe_event"
            decision["visible_alert_shown"] = bool(visible_alert.show)
            decision["alert_style"] = visible_alert.style
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=False,
                alert_suppression_reason="",
            )
            self._write_decision(decision)
            return decision
        try:
            last_dt = datetime.fromisoformat(last_timestamp)
            current_dt = datetime.fromisoformat(event.timestamp)
        except ValueError:
            event.notification_decision = "sent"
            event.notification_reason = "invalid_last_timestamp"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = True
            decision["decision"] = "sent"
            decision["reason"] = "invalid_last_timestamp"
            decision["visible_alert_shown"] = bool(visible_alert.show)
            decision["alert_style"] = visible_alert.style
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=False,
                alert_suppression_reason="",
            )
            self._write_decision(decision)
            return decision
        cooldown_seconds = int(preference.get("cooldown_seconds", settings["duplicate_rate_limit_seconds"]))
        allowed = (current_dt - last_dt).total_seconds() >= cooldown_seconds
        if not allowed:
            suppress_key = f"suppress:{event.event_type}:{event.process_name}:{event.pid}:{event.evidence[:64]}"
            count = int(self.db.get_background_monitor_state(suppress_key, "0") or "0") + 1
            self.db.set_background_monitor_state(suppress_key, str(count))
            decision["cooldown_suppressed"] = True
            event.cooldown_suppressed = True
            event.last_suppression_reason = "within_cooldown"
            remaining = max(0, cooldown_seconds - int((current_dt - last_dt).total_seconds()))
            decision["cooldown_remaining_seconds"] = remaining
            decision["decision"] = "suppressed_cooldown"
            decision["reason"] = "within_cooldown"
            event.notification_decision = "suppressed_cooldown"
            event.notification_reason = "within_cooldown"
            event.cooldown_remaining_seconds = remaining
            event.popup_allowed = True
            self.db.set_background_monitor_state(f"suppressed_notification_count:{event.event_type}", str(count))
            decision["alert_suppressed_reason"] = "within_cooldown"
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=True,
                alert_suppression_reason="within_cooldown",
            )
        else:
            decision["decision"] = "sent"
            decision["reason"] = "cooldown_elapsed"
            event.notification_decision = "sent"
            event.notification_reason = "cooldown_elapsed"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = True
            self._update_event_alert_trace(
                event,
                notification_policy_checked=True,
                notification_policy_result=decision["decision"],
                notification_policy_reason=decision["reason"],
                severity_before_policy=severity_before_policy,
                severity_after_policy=effective_severity,
                alert_required=bool(visible_alert.show),
                alert_suppressed=False,
                alert_suppression_reason="",
            )
        decision["visible_alert_shown"] = bool(visible_alert.show) and not decision["cooldown_suppressed"]
        decision["alert_style"] = visible_alert.style
        self._write_decision(decision)
        return decision

    def notify(self, event: BackgroundMonitorEvent, *, force: bool = False) -> tuple[bool, str]:
        event.original_event_type = getattr(event, "original_event_type", "") or event.event_type
        event.event_type = self._canonical_event_type(event)
        event.normalized_event_type = event.event_type
        if self._is_idle_notice_event(event):
            self.show_visible_security_alert(event, reason="authorized_use_notice")
            return self.notify_cfaa_idle_reminder(event)
        settings = self.settings()
        preference = self.preference_for(event.event_type)
        message = self._message(event)
        subtitle = "Security Event"
        priority = str(preference.get("severity", event.severity))
        notification_mode = str(preference.get("notification_mode", settings.get("notification_mode", "notification")))
        attempts: list[tuple[list[str], object]] = []
        self.show_visible_security_alert(event, reason=event.notification_reason or "policy")
        if notification_mode in {"notification", "both"}:
            script = (
                f'display notification "{applescript_escape(message)}" '
                f'with title "{applescript_escape("Mac Audit Agent")}" '
                f'subtitle "{applescript_escape(subtitle)}" '
                f'sound name "{applescript_escape(self._sound_for(event, settings))}"'
            )
            command = [OSASCRIPT_BIN, "-e", script]
            result = _run_osascript_command(command, runner=self.runner, timeout=5)
            attempts.append((command, result))
            self._log_attempt(event, priority, command, result, getattr(result, "returncode", 1) == 0)
            if getattr(result, "returncode", 1) != 0 and priority in {"high", "critical"} and notification_mode == "notification":
                self._write_fallback_log(
                    "macOS notification may be disabled. Check System Settings > Notifications for Terminal/Python/osascript or the packaged app."
                )
                dialog_command, dialog_result = self._run_dialog_attempt(message)
                attempts.append((dialog_command, dialog_result))
                self._log_attempt(event, priority, dialog_command, dialog_result, getattr(dialog_result, "returncode", 1) == 0)
        if notification_mode in {"dialog", "both"}:
            dialog_command, dialog_result = self._run_dialog_attempt(message)
            attempts.append((dialog_command, dialog_result))
            self._log_attempt(event, priority, dialog_command, dialog_result, getattr(dialog_result, "returncode", 1) == 0)
        overlay_attempted = True
        overlay_success = bool(getattr(event, "visible_alert_shown", False))
        dialog_attempted = any("display dialog" in " ".join(command) for command, _result in attempts)
        dialog_success = any("display dialog" in " ".join(command) and getattr(result, "returncode", 1) == 0 for command, result in attempts)
        notification_attempted = any("display notification" in " ".join(command) for command, _result in attempts)
        notification_success = any("display notification" in " ".join(command) and getattr(result, "returncode", 1) == 0 for command, result in attempts)
        delivery_method_used = "overlay" if overlay_success else ("dialog" if dialog_success else ("notification_center" if notification_success else "none"))
        success = any(getattr(result, "returncode", 1) == 0 for _command, result in attempts)
        if success:
            event.notification_sent = True
            event.notification_error = ""
            event.notification_returncode = 0
            if not force:
                self.db.set_background_monitor_state(self._last_key(event), event.timestamp)
                self.db.set_background_monitor_state("notification_status", self.status())
            self._record_alert_delivery(
                event,
                overlay_attempted=overlay_attempted,
                overlay_success=overlay_success,
                dialog_attempted=dialog_attempted,
                dialog_success=dialog_success,
                notification_attempted=notification_attempted,
                notification_success=notification_success,
                delivery_method_used=delivery_method_used,
            )
            return True, ""
        if getattr(event, "visible_alert_shown", False):
            event.notification_sent = True
            event.notification_error = ""
            event.notification_returncode = 0
            if not force:
                self.db.set_background_monitor_state(self._last_key(event), event.timestamp)
                self.db.set_background_monitor_state("notification_status", self.status())
            self._write_fallback_log(
                f"notification fallback: type={event.event_type} detail=visible alert shown; OS notification path unavailable"
            )
            self._record_alert_delivery(
                event,
                overlay_attempted=overlay_attempted,
                overlay_success=overlay_success,
                dialog_attempted=dialog_attempted,
                dialog_success=dialog_success,
                notification_attempted=notification_attempted,
                notification_success=notification_success,
                delivery_method_used=delivery_method_used,
            )
            return True, ""
        result = attempts[-1][1] if attempts else None
        detail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "notification failed").strip()
        if priority in {"high", "critical"}:
            detail = (
                f"{detail}\nmacOS notification may be disabled. Check System Settings > Notifications for Terminal/Python/osascript or the packaged app."
            ).strip()
        event.notification_sent = False
        event.notification_error = detail
        event.notification_returncode = getattr(result, "returncode", None)
        self.db.set_background_monitor_state("notification_status", f"failed: {detail}")
        self.db.set_background_monitor_state("last_error", f"Notification failed for {event.event_type}: {detail}")
        self._write_fallback_log(f"notification error: type={event.event_type} detail={detail}")
        self._record_alert_delivery(
            event,
            overlay_attempted=overlay_attempted,
            overlay_success=overlay_success,
            dialog_attempted=dialog_attempted,
            dialog_success=dialog_success,
            notification_attempted=notification_attempted,
            notification_success=notification_success,
            delivery_method_used=delivery_method_used,
        )
        return False, detail

    def update_security_overlay(self, event: BackgroundMonitorEvent) -> bool:
        decision = self.should_show_visible_alert(event)
        return self._dispatch_visible_alert(event, decision)

    def show_visible_security_alert(self, event: BackgroundMonitorEvent, reason: str = "", *, force: bool = False) -> bool:
        if reason:
            event.notification_reason = reason
        decision = self.should_show_visible_alert(event, force=force)
        return self._dispatch_visible_alert(event, decision)

    def _dispatch_visible_alert(self, event: BackgroundMonitorEvent, decision: AlertDecision) -> bool:
        self.db.set_background_monitor_state("overlay_dispatch_attempted", "1" if decision.show else "0")
        if not decision.show:
            event.visible_alert_shown = False
            self.db.set_background_monitor_state("overlay_dispatch_result", "skipped")
            self.db.set_background_monitor_state("overlay_manager_alive", "1" if self._security_overlay_pid_alive() else "0")
            self._record_alert_delivery(
                event,
                overlay_attempted=False,
                overlay_success=False,
                delivery_method_used="none",
            )
            self._update_event_alert_trace(
                event,
                overlay_dispatch_attempted=False,
                overlay_dispatch_at=datetime.now().astimezone().isoformat(),
                overlay_dispatch_result="skipped",
                overlay_error="",
                alert_required=False,
                alert_suppressed=True,
                alert_suppression_reason=event.last_suppression_reason or decision.reason,
                visible_alert_id="",
            )
            self._write_alert_pipeline_log(
                event,
                decision=event.notification_decision or "log_only",
                suppressed_reason=event.last_suppression_reason or decision.reason,
                overlay_dispatch_attempted=False,
                overlay_dispatch_result="skipped",
                overlay_error="",
            )
            return False
        state_path = OVERLAY_STATE_PATH
        state_path.parent.mkdir(parents=True, exist_ok=True)
        previous = {}
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
        same_type = previous.get("active", False) and previous.get("event_type") == event.event_type
        summary = event.evidence.strip().replace("\n", " ")
        payload = {
            "active": True,
            "event_type": event.event_type,
            "severity": event.severity,
            "style": decision.style,
            "title": self._overlay_title_for(event, decision),
            "details": self._overlay_details_for(event, decision),
            "summary": summary[:240] + ("..." if len(summary) > 240 else ""),
            "timestamp": event.timestamp,
            "count": int(previous.get("count", 0) or 0) + 1 if same_type else 1,
            "persistent": bool(decision.persistent),
            "dismiss_after_seconds": 0 if decision.persistent else self._overlay_auto_dismiss_seconds(decision.style),
            "visible_alert_shown": True,
            "alert_style": decision.style,
            "notification_decision": event.notification_decision or "log_only",
            "notification_reason": event.notification_reason or decision.reason,
            "cooldown_suppressed": bool(event.cooldown_suppressed),
            "cooldown_remaining_seconds": int(event.cooldown_remaining_seconds or 0),
            "buttons": self._overlay_buttons_for(event),
        }
        temporary = state_path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            temporary.replace(state_path)
        except OSError as exc:
            event.visible_alert_shown = False
            self.db.set_background_monitor_state("overlay_dispatch_result", "FAILED")
            self.db.set_background_monitor_state("last_overlay_exception", str(exc))
            self.db.set_background_monitor_state("last_overlay_error", str(exc))
            self._record_alert_delivery(
                event,
                overlay_attempted=True,
                overlay_success=False,
                delivery_method_used="overlay",
            )
            self._write_alert_pipeline_log(
                event,
                decision=event.notification_decision or decision.reason,
                suppressed_reason=event.last_suppression_reason or decision.reason,
                overlay_dispatch_attempted=True,
                overlay_dispatch_result="FAILED",
                overlay_error=str(exc),
            )
            return False
        event.visible_alert_id = getattr(event, "visible_alert_id", "") or event.event_id
        self.db.set_background_monitor_state("security_overlay_status", f"active: {event.event_type}")
        self.db.set_background_monitor_state("last_alert_decision", event.notification_decision or decision.reason)
        self.db.set_background_monitor_state("suppressed_alert_count", self.db.get_background_monitor_state("suppressed_alert_count", "0"))
        self.db.set_background_monitor_state("last_suppression_reason", event.last_suppression_reason or decision.reason)
        launched = self._ensure_security_overlay_process()
        event.visible_alert_shown = bool(launched)
        self.db.set_background_monitor_state("overlay_dispatch_result", "SUCCESS" if launched else "FAILED")
        self.db.set_background_monitor_state("overlay_manager_alive", "1" if launched or self._security_overlay_pid_alive() else "0")
        if not launched:
            count = int(self.db.get_background_monitor_state("overlay_error_count", "0") or "0") + 1
            self.db.set_background_monitor_state("overlay_error_count", str(count))
            self.db.set_background_monitor_state("last_overlay_exception", "overlay manager not running or failed to launch")
            self.db.set_background_monitor_state("last_overlay_error", "overlay manager not running or failed to launch")
        else:
            self.db.set_background_monitor_state("last_overlay_error", "")
            self.db.set_background_monitor_state("last_alert_displayed_at", event.timestamp)
            self.db.set_background_monitor_state(self._visible_alert_last_key(event), event.timestamp)
        self._record_alert_delivery(
            event,
            overlay_attempted=True,
            overlay_success=bool(launched),
            delivery_method_used="overlay" if launched else "none",
        )
        self._update_event_alert_trace(
            event,
            overlay_dispatch_attempted=True,
            overlay_dispatch_at=datetime.now().astimezone().isoformat(),
            overlay_dispatch_result="SUCCESS" if launched else "FAILED",
            overlay_error="" if launched else "overlay manager not running or failed to launch",
            alert_required=True,
            alert_suppressed=False if decision.show else True,
            alert_suppression_reason="" if decision.show else (event.last_suppression_reason or decision.reason),
            visible_alert_id=event.visible_alert_id,
            displayed_at=event.timestamp if launched else "",
        )
        self._write_alert_pipeline_log(
            event,
            decision=event.notification_decision or decision.reason,
            suppressed_reason=event.last_suppression_reason or decision.reason,
            overlay_dispatch_attempted=True,
            overlay_dispatch_result="SUCCESS" if launched else "FAILED",
            overlay_error="" if launched else "overlay manager not running or failed to launch",
        )
        return True

    def reconcile_security_overlay(self) -> bool:
        if self.db.get_background_monitor_state("security_overlay_enabled", "0") != "1":
            return False
        try:
            payload = json.loads(OVERLAY_STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.db.set_background_monitor_state("security_overlay_status", "inactive")
            return False
        if not payload.get("active", False):
            self.db.set_background_monitor_state("security_overlay_status", "inactive")
            return False
        self.db.set_background_monitor_state("security_overlay_status", f"active: {payload.get('event_type', 'security_event')}")
        launched = self._ensure_security_overlay_process()
        self.db.set_background_monitor_state("overlay_dispatch_attempted", "1")
        self.db.set_background_monitor_state("overlay_dispatch_result", "SUCCESS" if launched else "FAILED")
        self.db.set_background_monitor_state("overlay_manager_alive", "1" if launched or self._security_overlay_pid_alive() else "0")
        if not launched:
            self.db.set_background_monitor_state("last_overlay_error", "overlay manager not running or failed to launch")
        else:
            self.db.set_background_monitor_state("last_overlay_error", "")
        return True

    def _ensure_security_overlay_process(self) -> bool:
        if self._security_overlay_pid_alive():
            return True
        script_path = Path(__file__).resolve().parent / "security_overlay.py"
        try:
            process = self.popen_factory(
                [sys.executable, str(script_path), "--state-path", str(OVERLAY_STATE_PATH)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                env={**os.environ, **NOTIFICATION_PATH_ENV},
            )
            OVERLAY_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
            OVERLAY_PID_PATH.write_text(str(process.pid), encoding="utf-8")
            return True
        except OSError as exc:
            self._write_fallback_log(f"security overlay launch unavailable: {exc}")
            self.db.set_background_monitor_state("last_overlay_exception", str(exc))
            self.db.set_background_monitor_state("last_overlay_error", str(exc))
            return False

    def _security_overlay_pid_alive(self) -> bool:
        try:
            pid = int(OVERLAY_PID_PATH.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def _last_key(self, event: BackgroundMonitorEvent) -> str:
        return f"notify:{event.event_type}:{self._alert_signature(event)}"

    def _message(self, event: BackgroundMonitorEvent) -> str:
        evidence = event.evidence.strip().replace("\n", " ")
        evidence = evidence[:120] + ("..." if len(evidence) > 120 else "")
        protected_warning_events = {
            "input_activity_resumed_after_idle",
            "input_activity_idle_started",
            "usb_device_connected",
            "new_usb_device_detected",
            "bluetooth_device_connected",
            "network_ip_assigned",
            "vpn_connected",
            "system_moisture_detected",
            "display_wake",
            "display_sleep",
            "screen_locked",
            "screen_unlocked",
            "lid_opened",
            "lid_closed",
            "possible_lid_opened",
            "possible_lid_closed",
            "user_logged_in",
            "user_logged_out",
            "new_admin_user_detected",
            "launchdaemon_added",
            "launchagent_added",
            "persistence_item_created",
            "screen_sharing_enabled",
            "remote_login_enabled",
        }
        protected_prefix = (
            "Protected environment warning. Preserve logs and evidence. "
            if event.event_type in protected_warning_events
            else ""
        )
        return (
            f"{protected_prefix}{event.event_type} | {event.severity} | {evidence} | confidence={event.confidence}. "
            "Authorized use only. Activity is logged. Unauthorized access may violate policy and applicable law, "
            "including 18 U.S.C. 1030. This indicator is not a legal determination."
        )

    def _sound_for(self, event: BackgroundMonitorEvent, settings: dict[str, object]) -> str:
        if event.event_type in {"network_ip_assigned", "vpn_connected"}:
            return ""
        if event.event_type in {"usb_device_connected", "new_usb_device_detected"}:
            return self.db.get_background_monitor_state("usb_recognition_sound", "Pop") or "Pop"
        if event.event_type == "system_moisture_detected":
            return self.db.get_background_monitor_state("moisture_detection_sound", "Basso") or "Basso"
        return str(settings["notification_sound"])

    def _write_fallback_log(self, message: str) -> None:
        try:
            FALLBACK_MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
            with FALLBACK_MONITOR_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"{message}\n")
        except OSError:
            return

    def _write_alert_pipeline_log(
        self,
        event: BackgroundMonitorEvent,
        *,
        decision: str,
        suppressed_reason: str = "",
        overlay_dispatch_attempted: bool = False,
        overlay_dispatch_result: str = "",
        overlay_error: str = "",
    ) -> None:
        self._write_fallback_log(
            "[ALERT PIPELINE] "
            f"event_id={event.event_id} "
            f"event_type={event.event_type} "
            f"severity={event.severity} "
            f"notification_decision={decision} "
            f"alert_suppressed_reason={suppressed_reason or event.last_suppression_reason or ''} "
            f"overlay_dispatch_attempted={'yes' if overlay_dispatch_attempted else 'no'} "
            f"overlay_dispatch_result={overlay_dispatch_result or 'unknown'} "
            f"overlay_error={overlay_error or ''}"
        )

    def _run_dialog_attempt(self, message: str) -> tuple[list[str], object]:
        script = (
            f'display dialog "{applescript_escape(message)}" '
            f'with title "{applescript_escape("Mac Audit Agent - High Priority Event")}" '
            'buttons {"Acknowledge"} default button "Acknowledge" with icon caution'
        )
        command = [OSASCRIPT_BIN, "-e", script]
        result = _run_osascript_command(command, runner=self.runner, timeout=5)
        return command, result

    def _log_attempt(self, event: BackgroundMonitorEvent, priority: str, command: list[str], result, notification_sent: bool) -> None:
        stdout = (getattr(result, "stdout", "") or "").strip()
        stderr = (getattr(result, "stderr", "") or "").strip()
        returncode = getattr(result, "returncode", None)
        self._write_fallback_log(
            "notification attempt: "
            f"event_id={event.event_id} "
            f"event_type={event.event_type} "
            f"priority={priority} "
            f"command={' '.join(command)} "
            f"returncode={returncode} "
            f"stdout={stdout!r} "
            f"stderr={stderr!r} "
            f"notification_sent={notification_sent}"
        )

    def _write_decision(self, decision: dict[str, object]) -> None:
        self._write_fallback_log(
            "notification decision: "
            f"event_id={decision.get('event_id', '')} "
            f"event_type={decision['event_type']} "
            f"severity={decision['severity']} "
            f"priority={decision['priority']} "
            f"user_preference_loaded={decision['user_preference_loaded']} "
            f"notify={decision['notify']} "
            f"decision={decision['decision']} "
            f"reason={decision['reason']} "
            f"alert_suppressed_reason={decision.get('alert_suppressed_reason', '')} "
            f"popup_allowed={decision['popup_allowed']} "
            f"alert_style={decision['alert_style']} "
            f"cooldown_suppressed={decision['cooldown_suppressed']} "
            f"cooldown_remaining_seconds={decision['cooldown_remaining_seconds']} "
            f"visible_alert_shown={decision.get('visible_alert_shown', False)} "
            f"alert_style={decision.get('alert_style', 'neutral_grey')} "
            f"osascript_command={decision['command']!r} "
            f"returncode={decision['returncode']!r} "
            f"stderr={decision['stderr']!r} "
            f"notification_sent={decision['notification_sent']}"
        )

    def _record_alert_delivery(
        self,
        event: BackgroundMonitorEvent,
        *,
        overlay_attempted: bool = False,
        overlay_success: bool = False,
        dialog_attempted: bool = False,
        dialog_success: bool = False,
        notification_attempted: bool = False,
        notification_success: bool = False,
        delivery_method_used: str = "",
    ) -> None:
        try:
            self.db.record_alert_delivery(
                AlertDeliveryRecord(
                    event_id=event.event_id,
                    alert_type=event.event_type,
                    overlay_attempted=overlay_attempted,
                    overlay_success=overlay_success,
                    dialog_attempted=dialog_attempted,
                    dialog_success=dialog_success,
                    notification_attempted=notification_attempted,
                    notification_success=notification_success,
                    delivery_method_used=delivery_method_used,
                    updated_at=utc_now_iso(),
                    payload_json=json.dumps(
                        {
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "severity": event.severity,
                            "notification_decision": event.notification_decision,
                            "notification_reason": event.notification_reason,
                            "visible_alert_shown": bool(event.visible_alert_shown),
                            "alert_style": getattr(event, "alert_style", "neutral_grey"),
                        },
                        sort_keys=True,
                    ),
                )
            )
        except Exception:
            return

    def _overlay_title_for(self, event: BackgroundMonitorEvent, decision: AlertDecision) -> str:
        if event.event_type in {"input_activity_resumed_after_idle", "idle_resume_detected", "mouse_or_keyboard_activity_after_idle"}:
            return "Authorized Use Notice"
        if event.event_type in {"apple_security_forecast_elevated", "cve_forecast_level_increased"}:
            return "Apple Security Forecast"
        readable = event.event_type.replace("_", " ").strip().title()
        return readable or "Security Alert"

    def _overlay_details_for(self, event: BackgroundMonitorEvent, decision: AlertDecision) -> str:
        if event.event_type in {"input_activity_resumed_after_idle", "idle_resume_detected", "mouse_or_keyboard_activity_after_idle"}:
            return (
                "Activity was detected after a period of inactivity. "
                "If this system is under investigation, preserve logs and review the timeline before cleanup or shutdown."
            )
        if event.event_type in {"apple_security_forecast_elevated", "apple_security_forecast_urgent", "cve_forecast_level_increased"}:
            return "Apple-related security advisory or forecast changed. Review update guidance."
        return event.evidence or event.recommendation or "Review the event timeline."

    def _overlay_buttons_for(self, event: BackgroundMonitorEvent) -> list[str]:
        buttons = ["Acknowledge"]
        if event.event_type in {"input_activity_resumed_after_idle", "idle_resume_detected", "mouse_or_keyboard_activity_after_idle"}:
            buttons = ["Open Timeline", "Preserve Evidence Snapshot", "Acknowledge"]
        elif event.event_type in {"apple_security_forecast_elevated", "apple_security_forecast_urgent", "cve_forecast_level_increased"}:
            buttons = ["Open Timeline", "Acknowledge"]
        elif event.severity in {"high", "critical"}:
            buttons = ["Open Timeline", "Preserve Evidence Snapshot", "Acknowledge"]
        return buttons

    def _overlay_auto_dismiss_seconds(self, style: str) -> int:
        if style == "neutral_grey":
            return 10
        if style == "high_orange":
            return 12
        return 0

    def _visible_alert_last_key(self, event: BackgroundMonitorEvent) -> str:
        return f"visible_alert:{event.event_type}:{self._alert_signature(event)}"
