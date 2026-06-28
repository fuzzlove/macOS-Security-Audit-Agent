from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SETTINGS_STATE_KEY = "monitor_settings_json"
SETTINGS_LAST_SAVED_KEY = "monitor_settings_last_saved"
SETTINGS_LOADED_FROM_KEY = "monitor_settings_loaded_from"
SETTINGS_LAST_ERROR_KEY = "monitor_settings_last_error"
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_NOTIFICATION_MODES = {"none", "notification", "dialog", "both"}
VALID_MONITOR_MODES = {"user", "system", "protected"}


@dataclass
class InstallationSettings:
    monitor_mode: str = "user"
    user_launch_agent: bool = True
    system_launch_daemon: bool = False
    protected_mode: bool = False
    notifier: bool = True
    run_at_load: bool = True
    keep_alive: bool = True
    auto_restart: bool = True
    db_path: str = ""
    log_path: str = ""


@dataclass
class AlertingSettings:
    notify_all_events: bool = False
    notify_important_events: bool = True
    notify_min_severity: str = "info"
    popup_only_severe_events: bool = True
    browser_capture_process_popup: bool = False


@dataclass
class NotificationSettings:
    bottom_right_alerts: bool = True
    dialogs: bool = True
    notification_center: bool = True
    persistent_alerts: bool = True
    enable_alert_sounds: bool = False
    cooldown_seconds: int = 600
    duplicate_rate_limit_seconds: int = 10
    notification_mode: str = "notification"
    notification_sound: str = "Glass"
    authorized_use_warning: bool = True
    critical_overlay: bool = True


@dataclass
class EventCategorySettings:
    usb: bool = True
    bluetooth: bool = True
    camera: bool = True
    lid: bool = True
    session: bool = True
    mouse: bool = True
    keyboard: bool = True
    trackpad: bool = True
    network: bool = True
    persistence: bool = True
    admin: bool = True
    apple_exposure: bool = True
    monitor_health: bool = True


@dataclass
class AppleExposureSettings:
    enabled: bool = True


@dataclass
class IncidentResponseSettings:
    emergency_lockdown_policy: str = "recommend_only"


@dataclass
class EmergencyLockdownSettings:
    require_admin_approval: bool = True
    create_snapshot_first: bool = True


@dataclass
class EvidenceSettings:
    preserve_evidence: bool = True


@dataclass
class PerformanceSettings:
    idle_warning_minutes: int = 2


@dataclass
class DeveloperSettings:
    developer_mode: bool = False


@dataclass
class MonitorSettings:
    installation: InstallationSettings = field(default_factory=InstallationSettings)
    alerting: AlertingSettings = field(default_factory=AlertingSettings)
    notification: NotificationSettings = field(default_factory=NotificationSettings)
    event_categories: EventCategorySettings = field(default_factory=EventCategorySettings)
    apple_exposure: AppleExposureSettings = field(default_factory=AppleExposureSettings)
    incident_response: IncidentResponseSettings = field(default_factory=IncidentResponseSettings)
    emergency_lockdown: EmergencyLockdownSettings = field(default_factory=EmergencyLockdownSettings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    performance: PerformanceSettings = field(default_factory=PerformanceSettings)
    developer: DeveloperSettings = field(default_factory=DeveloperSettings)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CATEGORY_EVENT_TYPES: dict[str, set[str]] = {
    "usb": {"usb_device_connected", "usb_device_removed", "new_usb_device_detected", "usb_inventory_changed", "current_usb_device_inventory_changed"},
    "bluetooth": {"bluetooth_device_connected", "bluetooth_device_disconnected", "bluetooth_activity_started", "bluetooth_activity_stopped", "bluetooth_inventory_changed"},
    "camera": {"camera_activity_suspected", "camera_activity_confirmed", "camera_activity_stopped", "microphone_activity_suspected", "capture_capable_process_observed", "capture_capable_process_closed", "capture_process_observed"},
    "lid": {"lid_opened", "lid_closed", "possible_lid_opened", "possible_lid_closed", "clamshell_state_changed"},
    "session": {"display_wake", "display_sleep", "screen_unlocked", "screen_locked", "session_unlocked", "session_locked", "user_logged_in", "user_logged_out"},
    "mouse": {"mouse_activity_detected", "mouse_or_keyboard_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected"},
    "keyboard": {"keyboard_activity_detected", "mouse_or_keyboard_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected"},
    "trackpad": {"trackpad_activity_detected", "hid_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected", "unknown_hid_device_detected"},
    "network": {"network_ip_assigned", "new_ip_assigned", "network_interface_connected", "network_interface_disconnected", "new_network_connection_detected", "new_outbound_connection_detected", "new_inbound_connection_detected", "vpn_connected", "vpn_disconnected", "new_gateway_detected", "new_dns_server_detected", "remote_login_enabled", "screen_sharing_enabled"},
    "persistence": {"launchagent_added", "launchagent_removed", "launchdaemon_added", "launchdaemon_removed", "login_item_added", "persistence_item_created", "persistence_item_created_high_risk", "mitre_persistence_method_detected"},
    "admin": {"new_admin_user_detected", "admin_user_removed", "sudoers_changed", "admin_change_after_execution"},
    "apple_exposure": {"apple_security_forecast_elevated", "apple_security_forecast_urgent", "cve_forecast_level_increased"},
    "monitor_health": {"monitor_self_impact_warning", "protected_monitor_tamper_detected", "monitor_blindness_detected", "detector_stopped", "heartbeat_stale", "db_not_updating", "notifier_not_running"},
}


def _now() -> str:
    from mac_audit_agent.models import utc_now_iso

    return utc_now_iso()


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Any, default: int, minimum: int = 0, maximum: int = 86400) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _nested(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key, {})
    return value if isinstance(value, dict) else {}


def settings_from_dict(payload: dict[str, Any]) -> MonitorSettings:
    installation = _nested(payload, "installation")
    alerting = _nested(payload, "alerting")
    notification = _nested(payload, "notification")
    categories = _nested(payload, "event_categories")
    apple_exposure = _nested(payload, "apple_exposure")
    incident_response = _nested(payload, "incident_response")
    emergency_lockdown = _nested(payload, "emergency_lockdown")
    evidence = _nested(payload, "evidence")
    performance = _nested(payload, "performance")
    developer = _nested(payload, "developer")
    settings = MonitorSettings(
        installation=InstallationSettings(
            monitor_mode=_str(installation.get("monitor_mode"), "user"),
            user_launch_agent=_bool(installation.get("user_launch_agent"), True),
            system_launch_daemon=_bool(installation.get("system_launch_daemon"), False),
            protected_mode=_bool(installation.get("protected_mode"), False),
            notifier=_bool(installation.get("notifier"), True),
            run_at_load=_bool(installation.get("run_at_load"), True),
            keep_alive=_bool(installation.get("keep_alive"), True),
            auto_restart=_bool(installation.get("auto_restart"), True),
            db_path=_str(installation.get("db_path"), ""),
            log_path=_str(installation.get("log_path"), ""),
        ),
        alerting=AlertingSettings(
            notify_all_events=_bool(alerting.get("notify_all_events"), False),
            notify_important_events=_bool(alerting.get("notify_important_events"), True),
            notify_min_severity=_str(alerting.get("notify_min_severity"), "info"),
            popup_only_severe_events=_bool(alerting.get("popup_only_severe_events"), True),
            browser_capture_process_popup=_bool(alerting.get("browser_capture_process_popup"), False),
        ),
        notification=NotificationSettings(
            bottom_right_alerts=_bool(notification.get("bottom_right_alerts"), True),
            dialogs=_bool(notification.get("dialogs"), True),
            notification_center=_bool(notification.get("notification_center"), True),
            persistent_alerts=_bool(notification.get("persistent_alerts"), True),
            enable_alert_sounds=_bool(notification.get("enable_alert_sounds"), False),
            cooldown_seconds=_int(notification.get("cooldown_seconds"), 600),
            duplicate_rate_limit_seconds=_int(notification.get("duplicate_rate_limit_seconds"), 10),
            notification_mode=_str(notification.get("notification_mode"), "notification"),
            notification_sound=_str(notification.get("notification_sound"), "Glass"),
            authorized_use_warning=_bool(notification.get("authorized_use_warning"), True),
            critical_overlay=_bool(notification.get("critical_overlay"), True),
        ),
        event_categories=EventCategorySettings(**{name: _bool(categories.get(name), True) for name in EventCategorySettings.__dataclass_fields__}),
        apple_exposure=AppleExposureSettings(enabled=_bool(apple_exposure.get("enabled"), True)),
        incident_response=IncidentResponseSettings(emergency_lockdown_policy=_str(incident_response.get("emergency_lockdown_policy"), "recommend_only")),
        emergency_lockdown=EmergencyLockdownSettings(
            require_admin_approval=_bool(emergency_lockdown.get("require_admin_approval"), True),
            create_snapshot_first=_bool(emergency_lockdown.get("create_snapshot_first"), True),
        ),
        evidence=EvidenceSettings(preserve_evidence=_bool(evidence.get("preserve_evidence"), True)),
        performance=PerformanceSettings(idle_warning_minutes=_int(performance.get("idle_warning_minutes"), 2, minimum=1, maximum=1440)),
        developer=DeveloperSettings(developer_mode=_bool(developer.get("developer_mode"), False)),
        schema_version=_int(payload.get("schema_version"), 1, minimum=1, maximum=1),
    )
    return validate_settings(settings)


def default_settings() -> MonitorSettings:
    return MonitorSettings()


def validate_settings(settings: MonitorSettings) -> MonitorSettings:
    if settings.installation.monitor_mode not in VALID_MONITOR_MODES:
        settings.installation.monitor_mode = "user"
    if settings.installation.protected_mode:
        settings.installation.monitor_mode = "protected"
        settings.installation.system_launch_daemon = True
    if settings.installation.system_launch_daemon:
        settings.installation.user_launch_agent = False
    if settings.alerting.notify_min_severity not in VALID_SEVERITIES:
        settings.alerting.notify_min_severity = "info"
    if settings.notification.dialogs and settings.notification.notification_center:
        settings.notification.notification_mode = "both"
    elif settings.notification.dialogs:
        settings.notification.notification_mode = "dialog"
    elif settings.notification.notification_center:
        settings.notification.notification_mode = "notification"
    else:
        settings.notification.notification_mode = "none"
    if settings.notification.notification_mode not in VALID_NOTIFICATION_MODES:
        settings.notification.notification_mode = "notification"
    settings.notification.cooldown_seconds = _int(settings.notification.cooldown_seconds, 600)
    settings.notification.duplicate_rate_limit_seconds = _int(settings.notification.duplicate_rate_limit_seconds, 10)
    settings.performance.idle_warning_minutes = _int(settings.performance.idle_warning_minutes, 2, minimum=1, maximum=1440)
    return settings


def load_settings(db) -> MonitorSettings:
    raw = db.get_background_monitor_state(SETTINGS_STATE_KEY, "")
    if raw:
        try:
            settings = settings_from_dict(json.loads(raw))
            db.set_background_monitor_state(SETTINGS_LOADED_FROM_KEY, SETTINGS_STATE_KEY)
            db.set_background_monitor_state(SETTINGS_LAST_ERROR_KEY, "")
            return settings
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            db.set_background_monitor_state(SETTINGS_LAST_ERROR_KEY, f"corrupt settings recovered with defaults: {exc}")
    settings = settings_from_legacy_state(db)
    db.set_background_monitor_state(SETTINGS_LOADED_FROM_KEY, "legacy background_monitor_state defaults")
    return validate_settings(settings)


def save_settings(db, settings: MonitorSettings) -> MonitorSettings:
    settings = validate_settings(settings)
    db.set_background_monitor_state(SETTINGS_STATE_KEY, json.dumps(settings.to_dict(), sort_keys=True))
    db.set_background_monitor_state(SETTINGS_LAST_SAVED_KEY, _now())
    db.set_background_monitor_state(SETTINGS_LAST_ERROR_KEY, "")
    apply_settings_to_legacy_state(db, settings)
    return settings


def reset_defaults(db) -> MonitorSettings:
    return save_settings(db, default_settings())


def export_settings(db, path: Path) -> Path:
    settings = load_settings(db)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def import_settings(db, path: Path) -> MonitorSettings:
    settings = settings_from_dict(json.loads(path.read_text(encoding="utf-8")))
    return save_settings(db, settings)


def settings_from_legacy_state(db) -> MonitorSettings:
    notification_mode = db.get_background_monitor_state("notification_mode", "notification")
    monitor_mode = db.get_background_monitor_state("monitor_mode", db.get_background_monitor_state("monitor_install_mode", "user"))
    settings = MonitorSettings()
    settings.installation.monitor_mode = monitor_mode
    settings.installation.system_launch_daemon = monitor_mode in {"system", "protected"}
    settings.installation.protected_mode = monitor_mode == "protected"
    settings.installation.user_launch_agent = monitor_mode == "user"
    settings.installation.notifier = True
    settings.installation.db_path = db.get_background_monitor_state("db_path", str(getattr(db, "path", "")))
    settings.installation.log_path = db.get_background_monitor_state("log_path", "")
    settings.alerting.notify_all_events = db.get_background_monitor_state("notify_all_events", "0") == "1"
    settings.alerting.notify_important_events = db.get_background_monitor_state("notify_important_events", "1") != "0"
    settings.alerting.notify_min_severity = db.get_background_monitor_state("notify_min_severity", "info")
    settings.alerting.popup_only_severe_events = db.get_background_monitor_state("popup_only_severe_events", "1") != "0"
    settings.alerting.browser_capture_process_popup = db.get_background_monitor_state("browser_capture_process_popup", "0") == "1"
    settings.notification.bottom_right_alerts = db.get_background_monitor_state("show_visible_alerts", "1") != "0"
    settings.notification.dialogs = notification_mode in {"dialog", "both"}
    settings.notification.notification_center = notification_mode in {"notification", "both"}
    settings.notification.persistent_alerts = db.get_background_monitor_state("persistent_alerts", "1") != "0"
    settings.notification.enable_alert_sounds = db.get_background_monitor_state("enable_alert_sounds", "0") == "1"
    settings.notification.cooldown_seconds = _int(db.get_background_monitor_state("cooldown_seconds_per_category", "600"), 600)
    settings.notification.duplicate_rate_limit_seconds = _int(db.get_background_monitor_state("duplicate_rate_limit_seconds", "10"), 10)
    settings.notification.notification_mode = notification_mode
    settings.notification.notification_sound = db.get_background_monitor_state("notification_sound", "Glass")
    settings.notification.authorized_use_warning = db.get_background_monitor_state("cfaa_idle_warning_enabled", "1") != "0"
    settings.notification.critical_overlay = db.get_background_monitor_state("critical_overlay_enabled", db.get_background_monitor_state("show_visible_alerts", "1")) != "0"
    settings.performance.idle_warning_minutes = _int(db.get_background_monitor_state("idle_activity_warning_minutes", "2"), 2, minimum=1, maximum=1440)
    settings.event_categories.usb = db.get_background_monitor_state("show_usb_bluetooth_alerts", "1") != "0"
    settings.event_categories.bluetooth = db.get_background_monitor_state("show_usb_bluetooth_alerts", "1") != "0"
    settings.event_categories.camera = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.lid = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.session = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.mouse = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.keyboard = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.trackpad = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.network = db.get_background_monitor_state("show_network_change_alerts", "1") != "0"
    settings.event_categories.persistence = db.get_background_monitor_state("show_admin_persistence_alerts", "1") != "0"
    settings.event_categories.admin = db.get_background_monitor_state("show_admin_persistence_alerts", "1") != "0"
    settings.event_categories.apple_exposure = db.get_background_monitor_state("show_apple_forecast_alerts", "1") != "0"
    settings.apple_exposure.enabled = settings.event_categories.apple_exposure
    return validate_settings(settings)


def _enabled_categories(settings: MonitorSettings, names: set[str]) -> bool:
    return any(bool(getattr(settings.event_categories, name)) for name in names)


def apply_settings_to_legacy_state(db, settings: MonitorSettings) -> None:
    db.set_background_monitor_state("monitor_mode", settings.installation.monitor_mode)
    db.set_background_monitor_state("monitor_install_mode", settings.installation.monitor_mode)
    db.set_background_monitor_state("db_path", settings.installation.db_path or db.get_background_monitor_state("db_path", str(getattr(db, "path", ""))))
    if settings.installation.log_path:
        db.set_background_monitor_state("log_path", settings.installation.log_path)
    db.set_background_monitor_state("notify_all_events", "1" if settings.alerting.notify_all_events else "0")
    db.set_background_monitor_state("notify_important_events", "1" if settings.alerting.notify_important_events else "0")
    db.set_background_monitor_state("notify_min_severity", settings.alerting.notify_min_severity)
    db.set_background_monitor_state("popup_only_severe_events", "1" if settings.alerting.popup_only_severe_events else "0")
    db.set_background_monitor_state("browser_capture_process_popup", "1" if settings.alerting.browser_capture_process_popup else "0")
    db.set_background_monitor_state("show_visible_alerts", "1" if settings.notification.bottom_right_alerts else "0")
    db.set_background_monitor_state("persistent_alerts", "1" if settings.notification.persistent_alerts else "0")
    db.set_background_monitor_state("enable_alert_sounds", "1" if settings.notification.enable_alert_sounds else "0")
    db.set_background_monitor_state("critical_overlay_enabled", "1" if settings.notification.critical_overlay else "0")
    db.set_background_monitor_state("duplicate_rate_limit_seconds", str(settings.notification.duplicate_rate_limit_seconds))
    db.set_background_monitor_state("notification_mode", settings.notification.notification_mode)
    db.set_background_monitor_state("high_priority_alert_style", settings.notification.notification_mode)
    db.set_background_monitor_state("notification_sound", settings.notification.notification_sound or "Glass")
    db.set_background_monitor_state("cooldown_seconds_per_category", str(settings.notification.cooldown_seconds))
    db.set_background_monitor_state("idle_activity_warning_minutes", str(settings.performance.idle_warning_minutes))
    db.set_background_monitor_state("cfaa_idle_warning_enabled", "1" if settings.notification.authorized_use_warning else "0")
    db.set_background_monitor_state("show_physical_session_alerts", "1" if _enabled_categories(settings, {"camera", "lid", "session", "mouse", "keyboard", "trackpad"}) else "0")
    db.set_background_monitor_state("show_usb_bluetooth_alerts", "1" if _enabled_categories(settings, {"usb", "bluetooth", "trackpad"}) else "0")
    db.set_background_monitor_state("show_network_change_alerts", "1" if settings.event_categories.network else "0")
    db.set_background_monitor_state("show_admin_persistence_alerts", "1" if _enabled_categories(settings, {"admin", "persistence", "monitor_health"}) else "0")
    db.set_background_monitor_state("show_apple_forecast_alerts", "1" if settings.event_categories.apple_exposure else "0")
    db.set_background_monitor_state("developer_mode", "1" if settings.developer.developer_mode else "0")
    _apply_category_event_preferences(db, settings)


def _apply_category_event_preferences(db, settings: MonitorSettings) -> None:
    try:
        from mac_audit_agent.notification_manager import DEFAULT_EVENT_PREFERENCES
    except Exception:
        DEFAULT_EVENT_PREFERENCES = {}
    raw = db.get_background_monitor_state("event_preferences_json", "")
    try:
        preferences = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        preferences = {}
    if not isinstance(preferences, dict):
        preferences = {}
    for category, event_types in CATEGORY_EVENT_TYPES.items():
        enabled = bool(getattr(settings.event_categories, category))
        for event_type in event_types:
            base = dict(DEFAULT_EVENT_PREFERENCES.get(event_type, {}))
            current = preferences.get(event_type, {}) if isinstance(preferences.get(event_type), dict) else {}
            merged = {**base, **current}
            merged["enabled"] = enabled
            if not enabled:
                merged["notify"] = False
                merged["notification_mode"] = "none"
            elif str(merged.get("notification_mode", "none")) == "none" and bool(base.get("notify", False)):
                merged["notification_mode"] = str(base.get("notification_mode", "notification"))
                merged["notify"] = True
            preferences[event_type] = merged
    db.set_background_monitor_state("event_preferences_json", json.dumps(preferences, sort_keys=True))


def installed_monitor_values(db, *, launch_agent=None, system_launch_agent=None) -> dict[str, Any]:
    status = launch_agent.status() if launch_agent is not None else None
    system_status = system_launch_agent.status() if system_launch_agent is not None else None
    return {
        "monitor_mode": db.get_background_monitor_state("monitor_mode", "user"),
        "user_launch_agent_installed": bool(getattr(status, "installed", False)) if status is not None else None,
        "user_launch_agent_loaded": bool(getattr(status, "loaded", False)) if status is not None else None,
        "system_launch_daemon_installed": bool(getattr(system_status, "installed", False)) if system_status is not None else None,
        "system_launch_daemon_loaded": bool(getattr(system_status, "loaded", False)) if system_status is not None else None,
        "db_path": db.get_background_monitor_state("db_path", str(getattr(db, "path", ""))),
        "log_path": db.get_background_monitor_state("log_path", ""),
    }


def settings_diagnostics(db, settings: MonitorSettings, *, runtime_values: dict[str, Any] | None = None, installed_values: dict[str, Any] | None = None) -> dict[str, Any]:
    runtime_values = runtime_values or {}
    installed_values = installed_values or {}
    mismatches: list[str] = []
    if settings.alerting.notify_min_severity != runtime_values.get("notify_min_severity", settings.alerting.notify_min_severity):
        mismatches.append("notify_min_severity")
    if settings.notification.cooldown_seconds != int(runtime_values.get("cooldown_seconds_per_category", settings.notification.cooldown_seconds) or 0):
        mismatches.append("cooldown_seconds_per_category")
    expected_system = settings.installation.monitor_mode in {"system", "protected"}
    observed_system = installed_values.get("system_launch_daemon_installed")
    if observed_system is not None and expected_system != bool(observed_system):
        mismatches.append("system_launch_daemon_installation")
    return {
        "current_settings_json": settings.to_dict(),
        "loaded_from": db.get_background_monitor_state(SETTINGS_LOADED_FROM_KEY, ""),
        "last_saved": db.get_background_monitor_state(SETTINGS_LAST_SAVED_KEY, ""),
        "last_modified": db.get_background_monitor_state(SETTINGS_LAST_SAVED_KEY, ""),
        "last_error": db.get_background_monitor_state(SETTINGS_LAST_ERROR_KEY, ""),
        "current_runtime_values": runtime_values,
        "installed_monitor_values": installed_values,
        "mismatches": mismatches,
        "status": "mismatch" if mismatches else "ok",
    }
