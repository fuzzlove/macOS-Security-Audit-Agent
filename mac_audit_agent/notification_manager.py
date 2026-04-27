from __future__ import annotations

import subprocess
import json
from datetime import datetime
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorEvent


SEVERITY_LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
OSASCRIPT_BIN = "/usr/bin/osascript"
NOTIFICATION_PATH_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
IMPORTANT_EVENT_TYPES = {
    "camera_activity_suspected",
    "camera_activity_confirmed",
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
    "remote_login_enabled",
    "suspicious_process_observed",
    "persistence_item_created",
    "localhost_hidden_port_detected",
    "new_admin_user_detected",
    "packet_capture_started",
    "packet_capture_completed",
    "major_security_event",
    "monitor_self_test",
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
    "hidden_localhost_port_detected",
    "suspicious_root_process_observed",
    "remote_login_enabled",
    "screen_sharing_enabled",
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
    "camera_activity_confirmed": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "capture_capable_process_observed": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "possible_lid_opened": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "possible_lid_closed": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "user_logged_in": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "user_logged_out": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "screen_unlocked": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "remote_login_enabled": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "screen_sharing_enabled": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "suspicious_process_observed": {"enabled": True, "severity": "high", "notify": False, "cooldown_seconds": 600, "notification_mode": "none"},
    "launchagent_added": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "persistence_item_created": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "major_security_event": {"enabled": True, "severity": "high", "notify": True, "cooldown_seconds": 600, "notification_mode": "dialog"},
    "display_sleep": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "display_wake": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "screen_locked": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "screen_locked_state_changed": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "file_sharing_enabled": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "usb_device_connected": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "bluetooth_device_connected": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
    "capture_capable_process_closed": {"enabled": True, "severity": "medium", "notify": False, "cooldown_seconds": 0, "notification_mode": "none"},
}
FALLBACK_MONITOR_LOG = Path.home() / "Library" / "Logs" / "MacAuditAgent" / "monitor.log"


def applescript_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def send_notification(title, subtitle, message, sound="Glass", runner=None):
    script = (
        f'display notification "{applescript_escape(message)}" '
        f'with title "{applescript_escape(title)}" '
        f'subtitle "{applescript_escape(subtitle)}" '
        f'sound name "{applescript_escape(sound)}"'
    )
    runner = runner or subprocess.run
    return runner([OSASCRIPT_BIN, "-e", script], timeout=5, capture_output=True, text=True, env=NOTIFICATION_PATH_ENV)


def send_alert_dialog(title, message, runner=None):
    script = (
        f'display dialog "{applescript_escape(message)}" '
        f'with title "{applescript_escape(title)}" '
        'buttons {"Acknowledge"} default button "Acknowledge" with icon caution'
    )
    runner = runner or subprocess.run
    return runner([OSASCRIPT_BIN, "-e", script], timeout=5, capture_output=True, text=True, env=NOTIFICATION_PATH_ENV)


class NotificationManager:
    def __init__(self, db, runner=None) -> None:
        self.db = db
        self.runner = runner or subprocess.run

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
        preferences = self.event_preferences()
        default_cooldown = {"critical": 300, "high": 600, "medium": 0, "low": 0, "info": 0}
        preference = dict(preferences.get(event_type, {}))
        severity = str(preference.get("severity", "low"))
        preference.setdefault("enabled", True)
        preference.setdefault("notify", event_type in CRITICAL_POPUP_ALLOWLIST)
        preference.setdefault("cooldown_seconds", default_cooldown.get(severity, 1800))
        default_mode = "dialog" if severity in {"critical", "high"} and event_type in CRITICAL_POPUP_ALLOWLIST else ("notification" if severity == "medium" else "none")
        preference.setdefault("notification_mode", preference.get("alert_style", default_mode))
        return preference

    def status(self) -> str:
        return "available via AppleScript" if Path("/usr/bin/osascript").exists() else "unavailable"

    def should_notify(self, event: BackgroundMonitorEvent, *, force: bool = False) -> bool:
        decision = self.evaluate_notification_decision(event, force=force)
        return decision["notify"] and decision["decision"] == "sent"

    def _normalize_match_text(self, value: str) -> str:
        return "".join(ch for ch in value.lower() if ch.isalnum())

    def _is_browser_helper_process(self, event: BackgroundMonitorEvent) -> bool:
        haystacks = [event.process_name or "", event.evidence or ""]
        normalized = [self._normalize_match_text(value) for value in haystacks]
        normalized_keywords = {self._normalize_match_text(keyword) for keyword in BROWSER_HELPER_KEYWORDS}
        return any(any(keyword and keyword in value for keyword in normalized_keywords) for value in normalized)

    def should_popup(self, event: BackgroundMonitorEvent, preferences: dict[str, object] | None = None) -> tuple[bool, str]:
        settings = preferences if preferences is not None else self.settings()
        preference = self.preference_for(event.event_type)
        explicit_preferences = dict(settings.get("event_preferences", {}))
        explicit_preference = event.event_type in explicit_preferences
        severity = str(preference.get("severity", event.severity))
        event.severity = severity
        if not preference.get("enabled", True):
            return False, "disabled_by_user"
        if self._is_browser_helper_process(event) and not settings.get("browser_capture_process_popup", False):
            return False, "browser helper process logged silently"
        if explicit_preference and (
            not preference.get("notify", False) or str(preference.get("notification_mode", "none")) == "none"
        ):
            return False, "disabled_by_user"
        if explicit_preference and preference.get("notify", False) and preference.get("notification_mode", "none") != "none":
            return True, "user preference popup enabled"
        if event.event_type not in CRITICAL_POPUP_ALLOWLIST:
            return False, "event type is log-only by default"
        if severity not in {"high", "critical"}:
            return False, "severity below popup threshold"
        if settings.get("popup_only_severe_events", True):
            return True, "critical popup allowlist match"
        return bool(preference.get("notify", False)), "user popup policy override"

    def evaluate_notification_decision(self, event: BackgroundMonitorEvent, *, force: bool = False) -> dict[str, object]:
        settings = self.settings()
        preference = self.preference_for(event.event_type)
        explicit_preference = event.event_type in dict(settings.get("event_preferences", {}))
        effective_severity = str(preference.get("severity", event.severity))
        event.severity = effective_severity
        decision = {
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
        }
        if not preference.get("enabled", True):
            event.notification_decision = "disabled_by_user"
            event.notification_reason = "event_disabled_by_preference"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            self._write_decision(decision)
            decision["decision"] = "disabled_by_user"
            decision["reason"] = "event_disabled_by_preference"
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
            self._write_decision(decision)
            return decision
        popup_allowed, reason = self.should_popup(event, settings)
        decision["popup_allowed"] = popup_allowed
        event.popup_allowed = popup_allowed
        notify_candidate = popup_allowed and bool(preference.get("notify", False) or explicit_preference or event.event_type in CRITICAL_POPUP_ALLOWLIST)
        if not notify_candidate:
            event.notification_decision = "disabled_by_user" if reason == "disabled_by_user" else "log_only"
            event.notification_reason = reason
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            decision["decision"] = event.notification_decision
            decision["reason"] = reason
            self._write_decision(decision)
            return decision
        min_level = SEVERITY_LEVELS.get(str(settings["notify_min_severity"]), 0)
        if SEVERITY_LEVELS.get(effective_severity, 0) < min_level:
            event.notification_decision = "log_only"
            event.notification_reason = "below_min_severity"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = False
            decision["reason"] = "below_min_severity"
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
            self._write_decision(decision)
            return decision
        cooldown_seconds = int(preference.get("cooldown_seconds", settings["duplicate_rate_limit_seconds"]))
        allowed = (current_dt - last_dt).total_seconds() >= cooldown_seconds
        if not allowed:
            suppress_key = f"suppress:{event.event_type}:{event.process_name}:{event.pid}:{event.evidence[:64]}"
            count = int(self.db.get_background_monitor_state(suppress_key, "0") or "0") + 1
            self.db.set_background_monitor_state(suppress_key, str(count))
            decision["cooldown_suppressed"] = True
            remaining = max(0, cooldown_seconds - int((current_dt - last_dt).total_seconds()))
            decision["cooldown_remaining_seconds"] = remaining
            decision["decision"] = "suppressed_cooldown"
            decision["reason"] = "within_cooldown"
            event.notification_decision = "suppressed_cooldown"
            event.notification_reason = "within_cooldown"
            event.cooldown_remaining_seconds = remaining
            event.popup_allowed = True
            self.db.set_background_monitor_state(f"suppressed_notification_count:{event.event_type}", str(count))
        else:
            decision["decision"] = "sent"
            decision["reason"] = "cooldown_elapsed"
            event.notification_decision = "sent"
            event.notification_reason = "cooldown_elapsed"
            event.cooldown_remaining_seconds = 0
            event.popup_allowed = True
        self._write_decision(decision)
        return decision

    def notify(self, event: BackgroundMonitorEvent, *, force: bool = False) -> tuple[bool, str]:
        settings = self.settings()
        preference = self.preference_for(event.event_type)
        message = self._message(event)
        subtitle = "Security Event"
        priority = str(preference.get("severity", event.severity))
        notification_mode = str(preference.get("notification_mode", settings.get("notification_mode", "notification")))
        attempts: list[tuple[list[str], object]] = []
        if notification_mode in {"notification", "both"}:
            script = (
                f'display notification "{applescript_escape(message)}" '
                f'with title "{applescript_escape("Mac Audit Agent")}" '
                f'subtitle "{applescript_escape(subtitle)}" '
                f'sound name "{applescript_escape(str(settings["notification_sound"]))}"'
            )
            command = [OSASCRIPT_BIN, "-e", script]
            result = self.runner(command, timeout=5, capture_output=True, text=True, env=NOTIFICATION_PATH_ENV)
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
        success = any(getattr(result, "returncode", 1) == 0 for _command, result in attempts)
        if success:
            event.notification_sent = True
            event.notification_error = ""
            event.notification_returncode = 0
            if not force:
                self.db.set_background_monitor_state(self._last_key(event), event.timestamp)
            self.db.set_background_monitor_state("notification_status", self.status())
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
        return False, detail

    def _last_key(self, event: BackgroundMonitorEvent) -> str:
        return f"notify:{event.event_type}:{event.process_name}:{event.evidence[:64]}"

    def _message(self, event: BackgroundMonitorEvent) -> str:
        evidence = event.evidence.strip().replace("\n", " ")
        evidence = evidence[:120] + ("..." if len(evidence) > 120 else "")
        return f"{event.event_type} | {event.severity} | {evidence} | confidence={event.confidence}"

    def _write_fallback_log(self, message: str) -> None:
        try:
            FALLBACK_MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
            with FALLBACK_MONITOR_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"{message}\n")
        except OSError:
            return

    def _run_dialog_attempt(self, message: str) -> tuple[list[str], object]:
        script = (
            f'display dialog "{applescript_escape(message)}" '
            f'with title "{applescript_escape("Mac Audit Agent - High Priority Event")}" '
            'buttons {"Acknowledge"} default button "Acknowledge" with icon caution'
        )
        command = [OSASCRIPT_BIN, "-e", script]
        result = self.runner(command, timeout=5, capture_output=True, text=True, env=NOTIFICATION_PATH_ENV)
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
            f"event_type={decision['event_type']} "
            f"severity={decision['severity']} "
            f"priority={decision['priority']} "
            f"user_preference_loaded={decision['user_preference_loaded']} "
            f"notify={decision['notify']} "
            f"decision={decision['decision']} "
            f"reason={decision['reason']} "
            f"popup_allowed={decision['popup_allowed']} "
            f"alert_style={decision['alert_style']} "
            f"cooldown_suppressed={decision['cooldown_suppressed']} "
            f"cooldown_remaining_seconds={decision['cooldown_remaining_seconds']} "
            f"osascript_command={decision['command']!r} "
            f"returncode={decision['returncode']!r} "
            f"stderr={decision['stderr']!r} "
            f"notification_sent={decision['notification_sent']}"
        )
