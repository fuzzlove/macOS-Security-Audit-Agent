from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.settings.settings_reconciliation import reconcile_settings
from mac_audit_agent.settings.settings_versioning import monitor_mode_display


SETTINGS_STATE_KEY = "monitor_settings_json"
SETTINGS_LAST_SAVED_KEY = "monitor_settings_last_saved"
SETTINGS_LOADED_FROM_KEY = "monitor_settings_loaded_from"
SETTINGS_LAST_ERROR_KEY = "monitor_settings_last_error"
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_NOTIFICATION_MODES = {"none", "overlay", "notification", "dialog", "both"}
VALID_MONITOR_MODES = {"user", "system", "protected"}
VALID_PERSISTENT_LOCAL_EDR_MODES = {"user_agent", "system_daemon", "protected_system_daemon"}
VALID_USER_NOTIFIER_INSTALL_STATUS = {"installed", "missing", "loaded", "unloaded", "broken", "unknown"}


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
    dialogs: bool = False
    notification_center: bool = False
    persistent_alerts: bool = True
    enable_alert_sounds: bool = False
    cooldown_seconds: int = 600
    duplicate_rate_limit_seconds: int = 10
    notification_mode: str = "overlay"
    notification_sound: str = "Glass"
    authorized_use_warning: bool = True
    critical_overlay: bool = True


@dataclass
class UserNotifierSettings:
    enabled: bool = True
    auto_install: bool = True
    start_at_login: bool = True
    launch_agent_label: str = "com.mac-audit-agent.user-notifier"
    install_status: str = "unknown"
    last_install_at: str | None = None
    last_error: str | None = None


@dataclass
class LocalEDRSettings:
    persistent_local_edr_enabled: bool = True
    persistent_local_edr_mode: str = "user_agent"
    persistent_local_edr_alerts_enabled: bool = True
    persistent_local_edr_local_only: bool = True


@dataclass
class EventCategorySettings:
    usb_monitoring_enabled: bool = True
    bluetooth_monitoring_enabled: bool = True
    usb_alerts_enabled: bool = True
    bluetooth_alerts_enabled: bool = True
    usb_new_device_alerts_enabled: bool = True
    bluetooth_new_device_alerts_enabled: bool = True
    usb_trusted_device_alerts_enabled: bool = True
    bluetooth_trusted_device_alerts_enabled: bool = True
    usb_storage_alerts_enabled: bool = True
    usb_hid_alerts_enabled: bool = True
    usb_network_adapter_alerts_enabled: bool = True
    usb_unknown_device_alerts_enabled: bool = True
    bluetooth_inventory_alerts_enabled: bool = True
    bluetooth_unknown_device_alerts_enabled: bool = True
    admin_persistence_monitoring_enabled: bool = True
    network_activity_monitoring_enabled: bool = True
    admin_user_monitoring_enabled: bool = True
    sudoers_monitoring_enabled: bool = True
    persistence_monitoring_enabled: bool = True
    launchagent_monitoring_enabled: bool = True
    launchdaemon_monitoring_enabled: bool = True
    login_item_monitoring_enabled: bool = True
    profile_mdm_monitoring_enabled: bool = True
    network_connection_monitoring_enabled: bool = True
    network_new_connection_alerts_enabled: bool = True
    network_new_listener_alerts_enabled: bool = True
    network_dns_gateway_alerts_enabled: bool = True
    network_vpn_alerts_enabled: bool = True
    network_suspicious_connection_alerts_enabled: bool = True
    network_localhost_visibility_alerts_enabled: bool = True
    network_daemon_monitoring_enabled: bool = True
    vpn_monitoring_enabled: bool = True
    dns_gateway_monitoring_enabled: bool = True
    new_connection_alerts_enabled: bool = True
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
    user_notifier: UserNotifierSettings = field(default_factory=UserNotifierSettings)
    local_edr: LocalEDRSettings = field(default_factory=LocalEDRSettings)
    event_categories: EventCategorySettings = field(default_factory=EventCategorySettings)
    apple_exposure: AppleExposureSettings = field(default_factory=AppleExposureSettings)
    incident_response: IncidentResponseSettings = field(default_factory=IncidentResponseSettings)
    emergency_lockdown: EmergencyLockdownSettings = field(default_factory=EmergencyLockdownSettings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    performance: PerformanceSettings = field(default_factory=PerformanceSettings)
    developer: DeveloperSettings = field(default_factory=DeveloperSettings)
    schema_version: int = 1
    settings_version: int = 0
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CATEGORY_EVENT_TYPES: dict[str, set[str]] = {
    "usb": {
        "usb_device_connected",
        "usb_device_removed",
        "usb_inventory_changed",
        "current_usb_device_inventory_changed",
        "new_usb_device_detected",
        "trusted_usb_device_connected",
        "untrusted_usb_device_connected",
        "usb_device_reconnected",
        "usb_device_changed",
        "usb_storage_device_connected",
        "usb_hid_device_connected",
        "usb_keyboard_connected",
        "usb_mouse_connected",
        "usb_trackpad_connected",
        "usb_network_adapter_connected",
        "usb_camera_connected",
        "usb_microphone_connected",
        "usb_unknown_class_connected",
        "physical_device_connected",
        "physical_device_removed",
    },
    "bluetooth": {"bluetooth_device_connected", "bluetooth_device_disconnected", "bluetooth_activity_started", "bluetooth_activity_stopped", "bluetooth_inventory_changed", "unknown_bluetooth_device_detected"},
    "camera": {"camera_activity_suspected", "camera_activity_confirmed", "camera_activity_stopped", "microphone_activity_suspected", "microphone_activity_confirmed", "microphone_activity_stopped", "capture_device_connected", "capture_device_disconnected", "capture_capable_process_observed", "capture_capable_process_closed", "capture_process_observed"},
    "lid": {"lid_opened", "lid_closed", "possible_lid_opened", "possible_lid_closed", "clamshell_state_changed"},
    "session": {"display_wake", "display_sleep", "screen_unlocked", "screen_locked", "session_unlocked", "session_locked", "user_logged_in", "user_logged_out"},
    "mouse": {"mouse_activity_detected", "mouse_or_keyboard_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected"},
    "keyboard": {"keyboard_activity_detected", "mouse_or_keyboard_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected"},
    "trackpad": {"trackpad_activity_detected", "hid_activity_after_idle", "input_activity_after_idle", "input_activity_resumed_after_idle", "idle_resume_detected", "unknown_hid_device_detected"},
    "network": {
        "network_ip_assigned",
        "new_ip_assigned",
        "network_interface_connected",
        "network_interface_disconnected",
        "new_network_connection_detected",
        "new_outbound_connection_detected",
        "new_inbound_connection_detected",
        "suspicious_network_connection_detected",
        "suspicious_connection_detected",
        "hidden_localhost_port_detected",
        "localhost_hidden_port_detected",
        "localhost_visibility_mismatch_detected",
        "vpn_connected",
        "vpn_disconnected",
        "new_gateway_detected",
        "new_dns_server_detected",
        "remote_login_enabled",
        "screen_sharing_enabled",
    },
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
    user_notifier = _nested(payload, "user_notifier")
    local_edr = _nested(payload, "local_edr")
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
            dialogs=_bool(notification.get("dialogs"), False),
            notification_center=_bool(notification.get("notification_center"), False),
            persistent_alerts=_bool(notification.get("persistent_alerts"), True),
            enable_alert_sounds=_bool(notification.get("enable_alert_sounds"), False),
            cooldown_seconds=_int(notification.get("cooldown_seconds"), 600),
            duplicate_rate_limit_seconds=_int(notification.get("duplicate_rate_limit_seconds"), 10),
            notification_mode=_str(notification.get("notification_mode"), "overlay"),
            notification_sound=_str(notification.get("notification_sound"), "Glass"),
            authorized_use_warning=_bool(notification.get("authorized_use_warning"), True),
            critical_overlay=_bool(notification.get("critical_overlay"), True),
        ),
        user_notifier=UserNotifierSettings(
            enabled=_bool(user_notifier.get("enabled", payload.get("user_notifier_enabled")), True),
            auto_install=_bool(user_notifier.get("auto_install", payload.get("auto_install_user_notifier")), True),
            start_at_login=_bool(user_notifier.get("start_at_login"), True),
            launch_agent_label=_str(
                user_notifier.get("launch_agent_label", payload.get("user_notifier_launch_agent_label")),
                "com.mac-audit-agent.user-notifier",
            ),
            install_status=_str(user_notifier.get("install_status", payload.get("user_notifier_install_status")), "unknown"),
            last_install_at=user_notifier.get("last_install_at", payload.get("user_notifier_last_install_at")),
            last_error=user_notifier.get("last_error", payload.get("user_notifier_last_error")),
        ),
        local_edr=LocalEDRSettings(
            persistent_local_edr_enabled=_bool(local_edr.get("persistent_local_edr_enabled"), True),
            persistent_local_edr_mode=_str(local_edr.get("persistent_local_edr_mode"), "user_agent"),
            persistent_local_edr_alerts_enabled=_bool(local_edr.get("persistent_local_edr_alerts_enabled"), True),
            persistent_local_edr_local_only=_bool(local_edr.get("persistent_local_edr_local_only"), True),
        ),
        event_categories=EventCategorySettings(
            **{
                name: _bool(categories.get(name), True)
                for name in EventCategorySettings.__dataclass_fields__
            }
        ),
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
        settings_version=_int(payload.get("settings_version"), 0, minimum=0, maximum=2_147_483_647),
        updated_at=_str(payload.get("updated_at"), ""),
    )
    return validate_settings(settings)


def default_settings() -> MonitorSettings:
    return MonitorSettings()


def validate_settings(settings: MonitorSettings) -> MonitorSettings:
    if settings.installation.monitor_mode not in VALID_MONITOR_MODES:
        settings.installation.monitor_mode = "user"
    if settings.installation.monitor_mode == "protected" or settings.installation.protected_mode:
        settings.installation.monitor_mode = "protected"
        settings.installation.protected_mode = True
        settings.installation.system_launch_daemon = True
        settings.installation.user_launch_agent = False
    elif settings.installation.monitor_mode == "system" or settings.installation.system_launch_daemon:
        settings.installation.monitor_mode = "system"
        settings.installation.protected_mode = False
        settings.installation.system_launch_daemon = True
        settings.installation.user_launch_agent = False
    else:
        settings.installation.monitor_mode = "user"
        settings.installation.protected_mode = False
        settings.installation.system_launch_daemon = False
        settings.installation.user_launch_agent = True
    if settings.alerting.notify_min_severity not in VALID_SEVERITIES:
        settings.alerting.notify_min_severity = "info"
    if settings.notification.dialogs and settings.notification.notification_center:
        settings.notification.notification_mode = "both"
    elif settings.notification.dialogs:
        settings.notification.notification_mode = "dialog"
    elif settings.notification.notification_center:
        settings.notification.notification_mode = "notification"
    elif settings.notification.notification_mode not in {"overlay"}:
        settings.notification.notification_mode = "none"
    if settings.notification.notification_mode not in VALID_NOTIFICATION_MODES:
        settings.notification.notification_mode = "overlay"
    if settings.notification.bottom_right_alerts:
        settings.user_notifier.enabled = True
    if settings.user_notifier.launch_agent_label != "com.mac-audit-agent.user-notifier":
        settings.user_notifier.launch_agent_label = "com.mac-audit-agent.user-notifier"
    if settings.user_notifier.install_status not in VALID_USER_NOTIFIER_INSTALL_STATUS:
        settings.user_notifier.install_status = "unknown"
    if settings.local_edr.persistent_local_edr_mode not in VALID_PERSISTENT_LOCAL_EDR_MODES:
        settings.local_edr.persistent_local_edr_mode = {
            "user": "user_agent",
            "system": "system_daemon",
            "protected": "protected_system_daemon",
        }.get(settings.installation.monitor_mode, "user_agent")
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


def save_settings(db, settings: MonitorSettings, *, bump_version: bool = True) -> MonitorSettings:
    settings = validate_settings(settings)
    if bump_version:
        settings.settings_version = _int(settings.settings_version, 0, minimum=0, maximum=2_147_483_646) + 1
        settings.updated_at = _now()
    elif not settings.updated_at:
        settings.updated_at = _now()
    db.set_background_monitor_state(SETTINGS_STATE_KEY, json.dumps(settings.to_dict(), sort_keys=True))
    db.set_background_monitor_state(SETTINGS_LAST_SAVED_KEY, _now())
    db.set_background_monitor_state("settings_version", str(settings.settings_version))
    db.set_background_monitor_state("settings_updated_at", settings.updated_at)
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


def migrate_settings(db) -> MonitorSettings:
    settings = load_settings(db)
    return save_settings(db, settings)


def settings_from_legacy_state(db) -> MonitorSettings:
    notification_mode = db.get_background_monitor_state("notification_mode", "overlay")
    monitor_mode = db.get_background_monitor_state("monitor_mode", db.get_background_monitor_state("monitor_install_mode", "user"))
    settings = MonitorSettings()
    settings.installation.monitor_mode = monitor_mode
    settings.installation.system_launch_daemon = monitor_mode in {"system", "protected"}
    settings.installation.protected_mode = monitor_mode == "protected"
    settings.installation.user_launch_agent = monitor_mode == "user"
    settings.installation.user_launch_agent = db.get_background_monitor_state("installation_user_launch_agent", "1" if settings.installation.user_launch_agent else "0") != "0"
    settings.installation.system_launch_daemon = db.get_background_monitor_state("installation_system_launch_daemon", "1" if settings.installation.system_launch_daemon else "0") != "0"
    settings.installation.protected_mode = db.get_background_monitor_state("installation_protected_mode", "1" if settings.installation.protected_mode else "0") != "0"
    settings.installation.notifier = db.get_background_monitor_state("installation_notifier", "1") != "0"
    settings.installation.run_at_load = db.get_background_monitor_state("installation_run_at_load", "1") != "0"
    settings.installation.keep_alive = db.get_background_monitor_state("installation_keep_alive", "1") != "0"
    settings.installation.auto_restart = db.get_background_monitor_state("installation_auto_restart", "1") != "0"
    settings.installation.db_path = db.get_background_monitor_state("db_path", str(getattr(db, "path", "")))
    settings.installation.log_path = db.get_background_monitor_state("log_path", "")
    settings.local_edr.persistent_local_edr_enabled = db.get_background_monitor_state("persistent_local_edr_enabled", "1") != "0"
    settings.local_edr.persistent_local_edr_alerts_enabled = db.get_background_monitor_state("persistent_local_edr_alerts_enabled", db.get_background_monitor_state("show_visible_alerts", "1")) != "0"
    settings.local_edr.persistent_local_edr_local_only = db.get_background_monitor_state("persistent_local_edr_local_only", "1") != "0"
    settings.local_edr.persistent_local_edr_mode = db.get_background_monitor_state(
        "persistent_local_edr_mode",
        {"user": "user_agent", "system": "system_daemon", "protected": "protected_system_daemon"}.get(monitor_mode, "user_agent"),
    )
    settings.alerting.notify_all_events = db.get_background_monitor_state("notify_all_events", "0") == "1"
    settings.alerting.notify_important_events = db.get_background_monitor_state("notify_important_events", "1") != "0"
    settings.alerting.notify_min_severity = db.get_background_monitor_state("notify_min_severity", "info")
    settings.alerting.popup_only_severe_events = db.get_background_monitor_state("popup_only_severe_events", "1") != "0"
    settings.alerting.browser_capture_process_popup = db.get_background_monitor_state("browser_capture_process_popup", "0") == "1"
    settings.notification.bottom_right_alerts = db.get_background_monitor_state("show_visible_alerts", "1") != "0"
    settings.user_notifier.enabled = db.get_background_monitor_state("user_notifier_enabled", "1") != "0"
    settings.user_notifier.auto_install = db.get_background_monitor_state("auto_install_user_notifier", "1") != "0"
    settings.user_notifier.start_at_login = db.get_background_monitor_state("user_notifier_start_at_login", "1") != "0"
    settings.user_notifier.launch_agent_label = db.get_background_monitor_state("user_notifier_launch_agent_label", "com.mac-audit-agent.user-notifier")
    settings.user_notifier.install_status = db.get_background_monitor_state("user_notifier_install_status", "unknown")
    settings.user_notifier.last_install_at = db.get_background_monitor_state("user_notifier_last_install_at", "") or None
    settings.user_notifier.last_error = db.get_background_monitor_state("user_notifier_last_error", "") or None
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
    settings.event_categories.usb_monitoring_enabled = db.get_background_monitor_state(
        "usb_monitoring_enabled",
        "1" if settings.event_categories.usb else "0",
    ) != "0"
    settings.event_categories.bluetooth_monitoring_enabled = db.get_background_monitor_state(
        "bluetooth_monitoring_enabled",
        "1" if settings.event_categories.bluetooth else "0",
    ) != "0"
    settings.event_categories.usb_alerts_enabled = db.get_background_monitor_state("usb_alerts_enabled", "1") != "0"
    settings.event_categories.bluetooth_alerts_enabled = db.get_background_monitor_state("bluetooth_alerts_enabled", "1") != "0"
    settings.event_categories.usb_new_device_alerts_enabled = db.get_background_monitor_state("usb_new_device_alerts_enabled", "1") != "0"
    settings.event_categories.bluetooth_new_device_alerts_enabled = db.get_background_monitor_state("bluetooth_new_device_alerts_enabled", "1") != "0"
    settings.event_categories.usb_trusted_device_alerts_enabled = db.get_background_monitor_state("usb_trusted_device_alerts_enabled", "1") != "0"
    settings.event_categories.bluetooth_trusted_device_alerts_enabled = db.get_background_monitor_state("bluetooth_trusted_device_alerts_enabled", "1") != "0"
    settings.event_categories.usb_storage_alerts_enabled = db.get_background_monitor_state("usb_storage_alerts_enabled", "1") != "0"
    settings.event_categories.usb_hid_alerts_enabled = db.get_background_monitor_state("usb_hid_alerts_enabled", "1") != "0"
    settings.event_categories.usb_network_adapter_alerts_enabled = db.get_background_monitor_state("usb_network_adapter_alerts_enabled", "1") != "0"
    settings.event_categories.usb_unknown_device_alerts_enabled = db.get_background_monitor_state("usb_unknown_device_alerts_enabled", "1") != "0"
    settings.event_categories.bluetooth_inventory_alerts_enabled = db.get_background_monitor_state("bluetooth_inventory_alerts_enabled", "1") != "0"
    settings.event_categories.bluetooth_unknown_device_alerts_enabled = db.get_background_monitor_state("bluetooth_unknown_device_alerts_enabled", "1") != "0"
    settings.event_categories.camera = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.lid = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.session = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.mouse = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.keyboard = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.trackpad = db.get_background_monitor_state("show_physical_session_alerts", "1") != "0"
    settings.event_categories.network = db.get_background_monitor_state("show_network_change_alerts", "1") != "0"
    settings.event_categories.persistence = db.get_background_monitor_state("show_admin_persistence_alerts", "1") != "0"
    settings.event_categories.admin = db.get_background_monitor_state("show_admin_persistence_alerts", "1") != "0"
    settings.event_categories.network_activity_monitoring_enabled = db.get_background_monitor_state(
        "network_activity_monitoring_enabled",
        db.get_background_monitor_state("show_network_change_alerts", "1"),
    ) != "0"
    settings.event_categories.admin_persistence_monitoring_enabled = db.get_background_monitor_state(
        "admin_persistence_monitoring_enabled",
        db.get_background_monitor_state("show_admin_persistence_alerts", "1"),
    ) != "0"
    settings.event_categories.admin_user_monitoring_enabled = db.get_background_monitor_state("admin_user_monitoring_enabled", "1") != "0"
    settings.event_categories.sudoers_monitoring_enabled = db.get_background_monitor_state("sudoers_monitoring_enabled", "1") != "0"
    settings.event_categories.persistence_monitoring_enabled = db.get_background_monitor_state("persistence_monitoring_enabled", "1") != "0"
    settings.event_categories.launchagent_monitoring_enabled = db.get_background_monitor_state("launchagent_monitoring_enabled", "1") != "0"
    settings.event_categories.launchdaemon_monitoring_enabled = db.get_background_monitor_state("launchdaemon_monitoring_enabled", "1") != "0"
    settings.event_categories.login_item_monitoring_enabled = db.get_background_monitor_state("login_item_monitoring_enabled", "1") != "0"
    settings.event_categories.profile_mdm_monitoring_enabled = db.get_background_monitor_state("profile_mdm_monitoring_enabled", "1") != "0"
    settings.event_categories.network_connection_monitoring_enabled = db.get_background_monitor_state("network_connection_monitoring_enabled", "1") != "0"
    settings.event_categories.network_new_connection_alerts_enabled = db.get_background_monitor_state("network_new_connection_alerts_enabled", "1") != "0"
    settings.event_categories.network_new_listener_alerts_enabled = db.get_background_monitor_state("network_new_listener_alerts_enabled", "1") != "0"
    settings.event_categories.network_dns_gateway_alerts_enabled = db.get_background_monitor_state("network_dns_gateway_alerts_enabled", "1") != "0"
    settings.event_categories.network_vpn_alerts_enabled = db.get_background_monitor_state("network_vpn_alerts_enabled", "1") != "0"
    settings.event_categories.network_suspicious_connection_alerts_enabled = db.get_background_monitor_state("network_suspicious_connection_alerts_enabled", "1") != "0"
    settings.event_categories.network_localhost_visibility_alerts_enabled = db.get_background_monitor_state("network_localhost_visibility_alerts_enabled", "1") != "0"
    settings.event_categories.network_daemon_monitoring_enabled = db.get_background_monitor_state("network_daemon_monitoring_enabled", "1") != "0"
    settings.event_categories.vpn_monitoring_enabled = db.get_background_monitor_state("vpn_monitoring_enabled", "1") != "0"
    settings.event_categories.dns_gateway_monitoring_enabled = db.get_background_monitor_state("dns_gateway_monitoring_enabled", "1") != "0"
    settings.event_categories.new_connection_alerts_enabled = db.get_background_monitor_state("new_connection_alerts_enabled", "1") != "0"
    settings.event_categories.apple_exposure = db.get_background_monitor_state("show_apple_forecast_alerts", "1") != "0"
    settings.apple_exposure.enabled = settings.event_categories.apple_exposure
    return validate_settings(settings)


def _enabled_categories(settings: MonitorSettings, names: set[str]) -> bool:
    return any(bool(getattr(settings.event_categories, name)) for name in names)


def apply_settings_to_legacy_state(db, settings: MonitorSettings) -> None:
    db.set_background_monitor_state("monitor_mode", settings.installation.monitor_mode)
    db.set_background_monitor_state("monitor_install_mode", settings.installation.monitor_mode)
    db.set_background_monitor_state("persistent_local_edr_enabled", "1" if settings.local_edr.persistent_local_edr_enabled else "0")
    db.set_background_monitor_state("persistent_local_edr_alerts_enabled", "1" if settings.local_edr.persistent_local_edr_alerts_enabled else "0")
    db.set_background_monitor_state("persistent_local_edr_local_only", "1" if settings.local_edr.persistent_local_edr_local_only else "0")
    db.set_background_monitor_state("persistent_local_edr_mode", settings.local_edr.persistent_local_edr_mode)
    db.set_background_monitor_state("installation_user_launch_agent", "1" if settings.installation.user_launch_agent else "0")
    db.set_background_monitor_state("installation_system_launch_daemon", "1" if settings.installation.system_launch_daemon else "0")
    db.set_background_monitor_state("installation_protected_mode", "1" if settings.installation.protected_mode else "0")
    db.set_background_monitor_state("installation_notifier", "1" if settings.installation.notifier else "0")
    db.set_background_monitor_state("installation_run_at_load", "1" if settings.installation.run_at_load else "0")
    db.set_background_monitor_state("installation_keep_alive", "1" if settings.installation.keep_alive else "0")
    db.set_background_monitor_state("installation_auto_restart", "1" if settings.installation.auto_restart else "0")
    db.set_background_monitor_state("db_path", settings.installation.db_path or db.get_background_monitor_state("db_path", str(getattr(db, "path", ""))))
    if settings.installation.log_path:
        db.set_background_monitor_state("log_path", settings.installation.log_path)
    db.set_background_monitor_state("notify_all_events", "1" if settings.alerting.notify_all_events else "0")
    db.set_background_monitor_state("notify_important_events", "1" if settings.alerting.notify_important_events else "0")
    db.set_background_monitor_state("notify_min_severity", settings.alerting.notify_min_severity)
    db.set_background_monitor_state("popup_only_severe_events", "1" if settings.alerting.popup_only_severe_events else "0")
    db.set_background_monitor_state("browser_capture_process_popup", "1" if settings.alerting.browser_capture_process_popup else "0")
    db.set_background_monitor_state("show_visible_alerts", "1" if settings.notification.bottom_right_alerts else "0")
    db.set_background_monitor_state("user_notifier_enabled", "1" if settings.user_notifier.enabled else "0")
    db.set_background_monitor_state("auto_install_user_notifier", "1" if settings.user_notifier.auto_install else "0")
    db.set_background_monitor_state("user_notifier_start_at_login", "1" if settings.user_notifier.start_at_login else "0")
    db.set_background_monitor_state("user_notifier_launch_agent_label", settings.user_notifier.launch_agent_label)
    db.set_background_monitor_state("user_notifier_install_status", settings.user_notifier.install_status)
    db.set_background_monitor_state("user_notifier_last_install_at", settings.user_notifier.last_install_at or "")
    db.set_background_monitor_state("user_notifier_last_error", settings.user_notifier.last_error or "")
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
    db.set_background_monitor_state("usb_monitoring_enabled", "1" if settings.event_categories.usb_monitoring_enabled else "0")
    db.set_background_monitor_state("bluetooth_monitoring_enabled", "1" if settings.event_categories.bluetooth_monitoring_enabled else "0")
    db.set_background_monitor_state("usb_alerts_enabled", "1" if settings.event_categories.usb_alerts_enabled else "0")
    db.set_background_monitor_state("bluetooth_alerts_enabled", "1" if settings.event_categories.bluetooth_alerts_enabled else "0")
    db.set_background_monitor_state("usb_new_device_alerts_enabled", "1" if settings.event_categories.usb_new_device_alerts_enabled else "0")
    db.set_background_monitor_state("bluetooth_new_device_alerts_enabled", "1" if settings.event_categories.bluetooth_new_device_alerts_enabled else "0")
    db.set_background_monitor_state("usb_trusted_device_alerts_enabled", "1" if settings.event_categories.usb_trusted_device_alerts_enabled else "0")
    db.set_background_monitor_state("bluetooth_trusted_device_alerts_enabled", "1" if settings.event_categories.bluetooth_trusted_device_alerts_enabled else "0")
    db.set_background_monitor_state("usb_storage_alerts_enabled", "1" if settings.event_categories.usb_storage_alerts_enabled else "0")
    db.set_background_monitor_state("usb_hid_alerts_enabled", "1" if settings.event_categories.usb_hid_alerts_enabled else "0")
    db.set_background_monitor_state("usb_network_adapter_alerts_enabled", "1" if settings.event_categories.usb_network_adapter_alerts_enabled else "0")
    db.set_background_monitor_state("usb_unknown_device_alerts_enabled", "1" if settings.event_categories.usb_unknown_device_alerts_enabled else "0")
    db.set_background_monitor_state("bluetooth_inventory_alerts_enabled", "1" if settings.event_categories.bluetooth_inventory_alerts_enabled else "0")
    db.set_background_monitor_state("bluetooth_unknown_device_alerts_enabled", "1" if settings.event_categories.bluetooth_unknown_device_alerts_enabled else "0")
    db.set_background_monitor_state("admin_persistence_monitoring_enabled", "1" if settings.event_categories.admin_persistence_monitoring_enabled else "0")
    db.set_background_monitor_state("network_activity_monitoring_enabled", "1" if settings.event_categories.network_activity_monitoring_enabled else "0")
    for key in [
        "admin_user_monitoring_enabled",
        "sudoers_monitoring_enabled",
        "persistence_monitoring_enabled",
        "launchagent_monitoring_enabled",
        "launchdaemon_monitoring_enabled",
        "login_item_monitoring_enabled",
        "profile_mdm_monitoring_enabled",
        "network_connection_monitoring_enabled",
        "network_new_connection_alerts_enabled",
        "network_new_listener_alerts_enabled",
        "network_dns_gateway_alerts_enabled",
        "network_vpn_alerts_enabled",
        "network_suspicious_connection_alerts_enabled",
        "network_localhost_visibility_alerts_enabled",
        "network_daemon_monitoring_enabled",
        "vpn_monitoring_enabled",
        "dns_gateway_monitoring_enabled",
        "new_connection_alerts_enabled",
    ]:
        db.set_background_monitor_state(key, "1" if bool(getattr(settings.event_categories, key)) else "0")
    network_alerts_enabled = settings.event_categories.network_activity_monitoring_enabled and settings.event_categories.network
    admin_alerts_enabled = settings.event_categories.admin_persistence_monitoring_enabled and _enabled_categories(settings, {"admin", "persistence", "monitor_health"})
    db.set_background_monitor_state("show_network_change_alerts", "1" if network_alerts_enabled else "0")
    db.set_background_monitor_state("show_admin_persistence_alerts", "1" if admin_alerts_enabled else "0")
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
        if category == "usb" and not settings.event_categories.usb_monitoring_enabled:
            enabled = False
        if category == "bluetooth" and not settings.event_categories.bluetooth_monitoring_enabled:
            enabled = False
        if category in {"admin", "persistence"} and not settings.event_categories.admin_persistence_monitoring_enabled:
            enabled = False
        if category == "network" and not settings.event_categories.network_activity_monitoring_enabled:
            enabled = False
        for event_type in event_types:
            event_enabled = enabled
            suppression_reason = ""
            if event_enabled:
                if event_type == "new_usb_device_detected" and not settings.event_categories.usb_new_device_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_new_device_alerts_disabled"
                elif event_type == "trusted_usb_device_connected" and not settings.event_categories.usb_trusted_device_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_trusted_device_alerts_disabled"
                elif event_type == "usb_storage_device_connected" and not settings.event_categories.usb_storage_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_storage_alerts_disabled"
                elif event_type in {"usb_hid_device_connected", "usb_keyboard_connected", "usb_mouse_connected", "usb_trackpad_connected"} and not settings.event_categories.usb_hid_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_hid_alerts_disabled"
                elif event_type == "usb_network_adapter_connected" and not settings.event_categories.usb_network_adapter_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_network_adapter_alerts_disabled"
                elif event_type in {"untrusted_usb_device_connected", "usb_unknown_class_connected"} and not settings.event_categories.usb_unknown_device_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "usb_unknown_device_alerts_disabled"
                elif event_type == "bluetooth_device_connected" and not settings.event_categories.bluetooth_new_device_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "bluetooth_new_device_alerts_disabled"
                elif event_type in {"unknown_bluetooth_device_detected"} and not settings.event_categories.bluetooth_unknown_device_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "bluetooth_unknown_device_alerts_disabled"
                elif event_type == "bluetooth_inventory_changed" and not settings.event_categories.bluetooth_inventory_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "bluetooth_inventory_alerts_disabled"
                elif event_type in {"new_network_connection_detected", "new_outbound_connection_detected", "new_inbound_connection_detected"} and not settings.event_categories.network_new_connection_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_new_connection_alerts_disabled"
                elif event_type in {"remote_login_enabled", "screen_sharing_enabled"} and not settings.event_categories.network_new_listener_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_new_listener_alerts_disabled"
                elif event_type in {"hidden_localhost_port_detected", "localhost_hidden_port_detected", "localhost_visibility_mismatch_detected"} and not settings.event_categories.network_localhost_visibility_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_localhost_visibility_alerts_disabled"
                elif event_type in {"suspicious_network_connection_detected", "suspicious_connection_detected"} and not settings.event_categories.network_suspicious_connection_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_suspicious_connection_alerts_disabled"
                elif event_type in {"new_gateway_detected", "new_dns_server_detected"} and not settings.event_categories.network_dns_gateway_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_dns_gateway_alerts_disabled"
                elif event_type in {"vpn_connected", "vpn_disconnected"} and not settings.event_categories.network_vpn_alerts_enabled:
                    event_enabled = False
                    suppression_reason = "network_vpn_alerts_disabled"
                elif event_type in {"new_admin_user_detected", "admin_user_removed"} and not settings.event_categories.admin_user_monitoring_enabled:
                    event_enabled = False
                elif event_type == "sudoers_changed" and not settings.event_categories.sudoers_monitoring_enabled:
                    event_enabled = False
                elif event_type in {"launchagent_added", "launchagent_removed"} and not settings.event_categories.launchagent_monitoring_enabled:
                    event_enabled = False
                elif event_type in {"launchdaemon_added", "launchdaemon_removed"} and not settings.event_categories.launchdaemon_monitoring_enabled:
                    event_enabled = False
                elif event_type in {"login_item_added"} and not settings.event_categories.login_item_monitoring_enabled:
                    event_enabled = False
            base = dict(DEFAULT_EVENT_PREFERENCES.get(event_type, {}))
            current = preferences.get(event_type, {}) if isinstance(preferences.get(event_type), dict) else {}
            merged = {**base, **current}
            merged["enabled"] = event_enabled
            if not event_enabled:
                merged["notify"] = False
                merged["notification_mode"] = "none"
                if suppression_reason:
                    merged["suppression_reason"] = suppression_reason
            elif str(merged.get("notification_mode", "none")) == "none" and bool(base.get("notify", False)):
                merged["notification_mode"] = str(base.get("notification_mode", "overlay"))
                merged["notify"] = True
                merged.pop("suppression_reason", None)
            preferences[event_type] = merged
    db.set_background_monitor_state("event_preferences_json", json.dumps(preferences, sort_keys=True))


def installed_monitor_values(db, *, launch_agent=None, system_launch_agent=None) -> dict[str, Any]:
    status = launch_agent.status() if launch_agent is not None else None
    system_status = system_launch_agent.status() if system_launch_agent is not None else None
    return {
        "monitor_mode": db.get_background_monitor_state("monitor_mode", "user"),
        "persistent_local_edr_enabled": db.get_background_monitor_state("installed_persistent_local_edr_enabled", ""),
        "persistent_local_edr_alerts_enabled": db.get_background_monitor_state("installed_persistent_local_edr_alerts_enabled", ""),
        "persistent_local_edr_mode": db.get_background_monitor_state("installed_persistent_local_edr_mode", ""),
        "admin_persistence_monitoring_enabled": db.get_background_monitor_state("installed_admin_persistence_monitoring_enabled", ""),
        "network_activity_monitoring_enabled": db.get_background_monitor_state("installed_network_activity_monitoring_enabled", ""),
        "usb_monitoring_enabled": db.get_background_monitor_state("installed_usb_monitoring_enabled", ""),
        "bluetooth_monitoring_enabled": db.get_background_monitor_state("installed_bluetooth_monitoring_enabled", ""),
        "monitor_mode_installed": db.get_background_monitor_state("installed_monitor_mode", ""),
        "settings_version_installed": db.get_background_monitor_state("installed_settings_version", db.get_background_monitor_state("installed_monitor_settings_version", "")),
        "installed_manifest": db.get_background_monitor_state("installed_monitor_settings_manifest_json", ""),
        "notifier": db.get_background_monitor_state("installed_notifier", ""),
        "run_at_load": db.get_background_monitor_state("installed_run_at_load", ""),
        "keep_alive": db.get_background_monitor_state("installed_keep_alive", ""),
        "auto_restart": db.get_background_monitor_state("installed_auto_restart", ""),
        "user_launch_agent_installed": bool(getattr(status, "installed", False)) if status is not None else None,
        "user_launch_agent_loaded": bool(getattr(status, "loaded", False)) if status is not None else None,
        "system_launch_daemon_installed": bool(getattr(system_status, "installed", False)) if system_status is not None else None,
        "system_launch_daemon_loaded": bool(getattr(system_status, "loaded", False)) if system_status is not None else None,
        "db_path": db.get_background_monitor_state("db_path", str(getattr(db, "path", ""))),
        "log_path": db.get_background_monitor_state("log_path", ""),
        "user_notifier_install_status": db.get_background_monitor_state("user_notifier_install_status", "unknown"),
        "user_notifier_loaded": db.get_background_monitor_state("user_notifier_loaded", ""),
        "user_notifier_running": db.get_background_monitor_state("user_notifier_running", ""),
        "user_notifier_launchctl_domain": db.get_background_monitor_state("user_notifier_launchctl_domain", ""),
        "user_notifier_plist_path": db.get_background_monitor_state("user_notifier_plist_path", ""),
        "user_notifier_last_error": db.get_background_monitor_state("user_notifier_last_error", ""),
    }


def settings_diagnostics(db, settings: MonitorSettings, *, runtime_values: dict[str, Any] | None = None, installed_values: dict[str, Any] | None = None) -> dict[str, Any]:
    runtime_values = runtime_values or {}
    installed_values = installed_values or {}
    reconciliation = reconcile_settings(settings, runtime_values=runtime_values, installed_values=installed_values)
    mismatches: list[str] = []
    if settings.alerting.notify_min_severity != runtime_values.get("notify_min_severity", settings.alerting.notify_min_severity):
        mismatches.append("notify_min_severity")
    if settings.notification.cooldown_seconds != int(runtime_values.get("cooldown_seconds_per_category", settings.notification.cooldown_seconds) or 0):
        mismatches.append("cooldown_seconds_per_category")
    if settings.local_edr.persistent_local_edr_enabled != _bool(
        runtime_values.get("persistent_local_edr_enabled", runtime_values.get("runtime_persistent_local_edr_enabled")),
        settings.local_edr.persistent_local_edr_enabled,
    ):
        mismatches.append("persistent_local_edr_enabled")
    if settings.local_edr.persistent_local_edr_alerts_enabled != _bool(
        runtime_values.get("persistent_local_edr_alerts_enabled"),
        settings.local_edr.persistent_local_edr_alerts_enabled,
    ):
        mismatches.append("persistent_local_edr_alerts_enabled")
    if settings.event_categories.admin_persistence_monitoring_enabled != _bool(
        runtime_values.get("admin_persistence_monitoring_enabled"),
        settings.event_categories.admin_persistence_monitoring_enabled,
    ):
        mismatches.append("admin_persistence_monitoring_enabled")
    if settings.event_categories.network_activity_monitoring_enabled != _bool(
        runtime_values.get("network_activity_monitoring_enabled"),
        settings.event_categories.network_activity_monitoring_enabled,
    ):
        mismatches.append("network_activity_monitoring_enabled")
    if settings.event_categories.usb_monitoring_enabled != _bool(
        runtime_values.get("usb_monitoring_enabled", runtime_values.get("runtime_usb_monitoring_enabled")),
        settings.event_categories.usb_monitoring_enabled,
    ):
        mismatches.append("usb_monitoring_enabled")
    if settings.event_categories.bluetooth_monitoring_enabled != _bool(
        runtime_values.get("bluetooth_monitoring_enabled", runtime_values.get("runtime_bluetooth_monitoring_enabled")),
        settings.event_categories.bluetooth_monitoring_enabled,
    ):
        mismatches.append("bluetooth_monitoring_enabled")
    runtime_version = runtime_values.get("settings_version")
    if runtime_version not in {None, ""}:
        try:
            if int(runtime_version) != int(settings.settings_version):
                mismatches.append("runtime_settings_version")
        except (TypeError, ValueError):
            mismatches.append("runtime_settings_version")
    installed_edr = installed_values.get("persistent_local_edr_enabled")
    if installed_edr not in {None, ""} and settings.local_edr.persistent_local_edr_enabled != _bool(installed_edr):
        mismatches.append("installed_persistent_local_edr_enabled")
    installed_edr_alerts = installed_values.get("persistent_local_edr_alerts_enabled")
    if installed_edr_alerts not in {None, ""} and settings.local_edr.persistent_local_edr_alerts_enabled != _bool(installed_edr_alerts):
        mismatches.append("installed_persistent_local_edr_alerts_enabled")
    installed_edr_mode = installed_values.get("persistent_local_edr_mode")
    if installed_edr_mode not in {None, ""} and settings.local_edr.persistent_local_edr_mode != installed_edr_mode:
        mismatches.append("installed_persistent_local_edr_mode")
    installed_admin = installed_values.get("admin_persistence_monitoring_enabled")
    if installed_admin not in {None, ""} and settings.event_categories.admin_persistence_monitoring_enabled != _bool(installed_admin):
        mismatches.append("installed_admin_persistence_monitoring_enabled")
    installed_network = installed_values.get("network_activity_monitoring_enabled")
    if installed_network not in {None, ""} and settings.event_categories.network_activity_monitoring_enabled != _bool(installed_network):
        mismatches.append("installed_network_activity_monitoring_enabled")
    installed_usb = installed_values.get("usb_monitoring_enabled")
    if installed_usb not in {None, ""} and settings.event_categories.usb_monitoring_enabled != _bool(installed_usb):
        mismatches.append("installed_usb_monitoring_enabled")
    installed_bluetooth = installed_values.get("bluetooth_monitoring_enabled")
    if installed_bluetooth not in {None, ""} and settings.event_categories.bluetooth_monitoring_enabled != _bool(installed_bluetooth):
        mismatches.append("installed_bluetooth_monitoring_enabled")
    installed_version = installed_values.get("settings_version_installed")
    if installed_version not in {None, ""}:
        try:
            if int(installed_version) != int(settings.settings_version):
                mismatches.append("installed_settings_version")
        except (TypeError, ValueError):
            mismatches.append("installed_settings_version")
    installed_mode = installed_values.get("monitor_mode_installed")
    if installed_mode not in {None, ""} and settings.installation.monitor_mode != installed_mode:
        mismatches.append("installed_monitor_mode")
    for field_name in ["notifier", "run_at_load", "keep_alive", "auto_restart"]:
        installed_value = installed_values.get(field_name)
        if installed_value not in {None, ""} and bool(getattr(settings.installation, field_name)) != _bool(installed_value):
            mismatches.append(f"installed_{field_name}")
    expected_system = settings.installation.monitor_mode in {"system", "protected"}
    observed_system = installed_values.get("system_launch_daemon_installed")
    if observed_system is not None and expected_system != bool(observed_system):
        mismatches.append("system_launch_daemon_installation")
    notifier_required = (
        settings.local_edr.persistent_local_edr_enabled
        and settings.notification.bottom_right_alerts
        and settings.user_notifier.enabled
    )
    notifier_status = str(runtime_values.get("user_notifier_install_status") or installed_values.get("user_notifier_install_status") or "unknown")
    if notifier_status == "loaded_running":
        notifier_status_display = "loaded"
    else:
        notifier_status_display = notifier_status
    notifier_loaded = _bool(runtime_values.get("user_notifier_loaded", installed_values.get("user_notifier_loaded")), False)
    notifier_running = _bool(runtime_values.get("user_notifier_running", installed_values.get("user_notifier_running")), False)
    from mac_audit_agent.runtime.topology import resolve_runtime_topology
    topology = resolve_runtime_topology(db.path, selected_mode=settings.installation.monitor_mode, notifier_event_database=Path(str(runtime_values.get("user_notifier_db_path", ""))).expanduser() if runtime_values.get("user_notifier_db_path") else None)
    try:
        heartbeat_age = float(runtime_values.get("user_notifier_active_db_heartbeat_age_seconds", ""))
    except (TypeError, ValueError):
        heartbeat_age = float("inf")
    deliverability_predicates = {
        "service_loaded": notifier_loaded,
        "process_running": notifier_running,
        "heartbeat_fresh": heartbeat_age <= 90,
        "executable_valid": _bool(runtime_values.get("user_notifier_executable_valid"), False),
        "launch_arguments_valid": _bool(runtime_values.get("user_notifier_launch_arguments_valid"), False),
        "topology_aligned": topology.aligned,
        "input_source_readable": _bool(runtime_values.get("user_notifier_source_readable"), False),
        "receipt_store_writable": _bool(runtime_values.get("user_notifier_receipt_store_writable"), False),
        "settings_version_aligned": "notifier" not in reconciliation.stale_components,
        "build_identity_aligned": _bool(runtime_values.get("user_notifier_build_identity_aligned"), False),
        "current_diagnostic_event_received": _bool(runtime_values.get("user_notifier_current_diagnostic_event_received"), False),
        "render_path_available": _bool(runtime_values.get("user_notifier_render_path_available"), False),
    }
    notifier_deliverable = (not notifier_required) or all(deliverability_predicates.values())
    if notifier_required and not notifier_deliverable:
        mismatches.append("user_notifier_not_deliverable")
    for component in reconciliation.stale_components:
        legacy_name = {
            "runtime": "runtime_settings_version",
            "notifier": "notifier_settings_version",
            "installed_manifest": "installed_settings_version",
        }.get(component)
        if legacy_name and legacy_name not in mismatches:
            mismatches.append(legacy_name)
    status = "ok" if reconciliation.status in {"synced", "installed_manifest_stale"} and not any(item not in {"installed_settings_version"} for item in mismatches) else reconciliation.status
    mode_internal = settings.installation.monitor_mode
    return {
        "current_settings_json": settings.to_dict(),
        "loaded_from": db.get_background_monitor_state(SETTINGS_LOADED_FROM_KEY, ""),
        "last_saved": db.get_background_monitor_state(SETTINGS_LAST_SAVED_KEY, ""),
        "last_modified": db.get_background_monitor_state(SETTINGS_LAST_SAVED_KEY, ""),
        "last_error": db.get_background_monitor_state(SETTINGS_LAST_ERROR_KEY, ""),
        "current_runtime_values": runtime_values,
        "installed_monitor_values": installed_values,
        "historical_installed_state": {
            "user_notifier_install_status": installed_values.get("user_notifier_install_status", ""),
            "user_notifier_loaded": installed_values.get("user_notifier_loaded", ""),
            "user_notifier_running": installed_values.get("user_notifier_running", ""),
            "settings_version_installed": installed_values.get("settings_version_installed", ""),
            "source": "installed_monitor_values",
        },
        "settings_sync_status": {
            "ui_settings_version": reconciliation.ui_settings_version,
            "runtime_settings_version": reconciliation.runtime_settings_version,
            "installed_manifest_settings_version": reconciliation.installed_manifest_settings_version,
            "notifier_settings_version": reconciliation.notifier_settings_version,
            "effective_settings_version": reconciliation.effective_settings_version,
            "last_saved": db.get_background_monitor_state(SETTINGS_LAST_SAVED_KEY, ""),
            "last_runtime_reload": runtime_values.get("last_settings_reload_time", ""),
            "last_notifier_reload": runtime_values.get("notifier_last_settings_reload_time", runtime_values.get("last_settings_reload_time", "")),
            "last_monitor_repair": installed_values.get("last_repaired_at", ""),
        },
        "settings_reconciliation": reconciliation.to_dict(),
        "settings_component_status": [
            {
                "component": "UI Settings",
                "version": reconciliation.ui_settings_version,
                "status": "current",
                "source": "current_settings_json.settings_version",
                "repair_action": "Save settings again if this value is missing.",
            },
            {
                "component": "System Daemon Runtime",
                "version": reconciliation.runtime_settings_version,
                "status": "stale" if "runtime" in reconciliation.stale_components else "current",
                "source": "current_runtime_values.settings_version",
                "repair_action": "Apply Settings to Runtime / Restart Background Monitor",
            },
            {
                "component": "User Notifier Runtime",
                "version": reconciliation.notifier_settings_version,
                "status": "stale" if "notifier" in reconciliation.stale_components else "current",
                "source": "current_runtime_values.notifier_settings_version",
                "repair_action": "Restart User Notifier",
            },
            {
                "component": "Installed Monitor Manifest",
                "version": reconciliation.installed_manifest_settings_version,
                "status": "stale" if "installed_manifest" in reconciliation.stale_components else "current",
                "source": "installed_monitor_values.installed_manifest.settings_version",
                "repair_action": "Repair Background Monitor / Rebuild Installed Manifest",
            },
            {
                "component": "User Alert Agent",
                "version": "",
                "status": "running" if notifier_running else ("loaded" if notifier_loaded else notifier_status_display),
                "source": runtime_values.get("user_notifier_status_source", "runtime_values"),
                "repair_action": "Repair User Alert Agent" if notifier_required and not notifier_running else "No repair required.",
            },
        ],
        "monitor_mode_internal": mode_internal,
        "monitor_mode_display": monitor_mode_display(mode_internal),
        "active_runtime_domain": "system" if mode_internal in {"system", "protected"} else mode_internal,
        "mismatches": mismatches,
        "detailed_mismatches": [item.to_dict() for item in reconciliation.mismatches],
        "repair_actions": reconciliation.repair_actions,
        "user_alert_agent": {
            "required": notifier_required,
            "status": notifier_status_display,
            "loaded": notifier_loaded,
            "running": notifier_running,
            "plist_path": runtime_values.get("user_notifier_plist_path", installed_values.get("user_notifier_plist_path", "")),
            "launchctl_domain": runtime_values.get("user_notifier_launchctl_domain", installed_values.get("user_notifier_launchctl_domain", "")),
            "last_error": runtime_values.get("user_notifier_last_error", installed_values.get("user_notifier_last_error", "")),
            "deliverable": notifier_deliverable,
            "deliverability_predicates": deliverability_predicates,
            "topology_error_codes": list(topology.error_codes),
            "source": runtime_values.get("user_notifier_status_source", "runtime_values"),
            "active_db_heartbeat": runtime_values.get("user_notifier_active_db_heartbeat", ""),
            "active_db_heartbeat_age_seconds": runtime_values.get("user_notifier_active_db_heartbeat_age_seconds", ""),
            "historical_stdout_heartbeat_detected": runtime_values.get("user_notifier_historical_stdout_heartbeat_detected", ""),
            "stale_log_evidence": runtime_values.get("user_notifier_stale_log_evidence", ""),
        },
        "status": "settings_synced_but_notifier_unavailable" if notifier_required and not notifier_deliverable else status,
    }
