from __future__ import annotations

from copy import deepcopy

from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.monitor_settings import load_settings, save_settings, settings_diagnostics
from mac_audit_agent.storage import AuditDatabase


SETTING_PATHS = {
    "persistent_local_edr_enabled": ("local_edr", "persistent_local_edr_enabled"),
    "bottom_right_alerts_enabled": ("notification", "bottom_right_alerts"),
    "user_notifier_enabled": ("user_notifier", "enabled"),
    "auto_install_user_notifier": ("user_notifier", "auto_install"),
    "usb_monitoring_enabled": ("event_categories", "usb_monitoring_enabled"),
    "bluetooth_monitoring_enabled": ("event_categories", "bluetooth_monitoring_enabled"),
    "network_activity_monitoring_enabled": ("event_categories", "network_activity_monitoring_enabled"),
    "admin_persistence_monitoring_enabled": ("event_categories", "admin_persistence_monitoring_enabled"),
    "minimum_alert_severity": ("alerting", "notify_min_severity"),
    "authorized_use_warning_enabled": ("notification", "authorized_use_warning"),
    "emergency_lockdown_policy": ("incident_response", "emergency_lockdown_policy"),
}


def run_settings_audit(context: AuditContext) -> list[FunctionalCheck]:
    db = AuditDatabase(context.db_path)
    checks: list[FunctionalCheck] = []
    base = FunctionalCheck(
        check_id="settings.enforcement",
        feature_area="Settings",
        name="settings enforcement",
        description="Critical settings persist, reload, and appear in diagnostics.",
        severity_if_failed="blocker",
        test_type="settings",
        expected_result="Defaults exist, save/reload increments version, runtime diagnostics expose values.",
    )
    try:
        settings = load_settings(db)
        before_version = int(settings.settings_version or 0)
        original = deepcopy(settings)
        settings.event_categories.usb_monitoring_enabled = not bool(settings.event_categories.usb_monitoring_enabled)
        saved = save_settings(db, settings)
        reloaded = load_settings(db)
        save_settings(db, original)
        diagnostics = settings_diagnostics(db, load_settings(db), runtime_values=NotificationManager(db).settings())
        missing = [name for name, path in SETTING_PATHS.items() if not hasattr(getattr(reloaded, path[0]), path[1])]
        version_incremented = int(saved.settings_version or 0) == before_version + 1
        usb_changed = reloaded.event_categories.usb_monitoring_enabled == settings.event_categories.usb_monitoring_enabled
        evidence = {
            "checked_settings": sorted(SETTING_PATHS),
            "settings_version_before": before_version,
            "settings_version_after": saved.settings_version,
            "diagnostics_keys": sorted(diagnostics.keys()),
        }
        if missing:
            checks.append(base.failed(f"Missing setting defaults: {', '.join(missing)}", "Add missing defaults to MonitorSettings and legacy state migration.", evidence))
        elif not version_incremented or not usb_changed:
            checks.append(base.failed("Settings did not persist/reload with version increment.", "Connect visible settings to save_settings/load_settings and ensure settings_version increments.", evidence))
        else:
            checks.append(base.passed("Settings defaults, persistence, reload, versioning, and diagnostics verified.", evidence))
    except Exception as exc:
        checks.append(base.failed(str(exc), "Fix MonitorSettings load/save diagnostics before user testing.", {"exception": type(exc).__name__}))
    return checks
