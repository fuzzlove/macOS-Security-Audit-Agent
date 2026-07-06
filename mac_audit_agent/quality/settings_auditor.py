from __future__ import annotations

from copy import deepcopy

from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.monitor_settings import installed_monitor_values, load_settings, save_settings, settings_diagnostics
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_status import canonical_user_notifier_status, status_to_runtime_values


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
        save_settings(db, original, bump_version=False)
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
        checks.extend(_settings_reconciliation_checks(db))
    except Exception as exc:
        checks.append(base.failed(str(exc), "Fix MonitorSettings load/save diagnostics before user testing.", {"exception": type(exc).__name__}))
    return checks


def _settings_reconciliation_checks(db: AuditDatabase) -> list[FunctionalCheck]:
    settings = load_settings(db)
    runtime_values = NotificationManager(db).settings()
    runtime_values.setdefault("settings_version", db.get_background_monitor_state("settings_version", ""))
    runtime_values.setdefault("daemon_settings_version", db.get_background_monitor_state("settings_version", ""))
    runtime_values.setdefault("notifier_settings_version", runtime_values.get("settings_version", ""))
    try:
        active_db_path = get_active_monitor_db_path(db.path)
        live_status = canonical_user_notifier_status(db_path=active_db_path)
        runtime_values.update(status_to_runtime_values(live_status))
    except Exception as exc:
        runtime_values.setdefault("user_notifier_status_source", "live_status_error")
        runtime_values.setdefault("user_notifier_last_error", str(exc))
        for key in ["user_notifier_install_status", "user_notifier_loaded", "user_notifier_running"]:
            runtime_values.setdefault(key, db.get_background_monitor_state(key, ""))
    diagnostics = settings_diagnostics(db, settings, runtime_values=runtime_values, installed_values=installed_monitor_values(db))
    reconciliation = diagnostics.get("settings_reconciliation", {})
    checks: list[FunctionalCheck] = []

    version_check = FunctionalCheck(
        "settings.version_alignment",
        "Settings",
        "settings version alignment",
        "UI, daemon runtime, notifier runtime, and installed manifest settings versions are reconciled.",
        "high",
        "settings",
    )
    stale = set(reconciliation.get("stale_components", []))
    if stale & {"runtime", "notifier"}:
        checks.append(version_check.failed("Runtime settings are stale after diagnostics refresh.", "Use Repair Settings Sync, then restart stale daemon/notifier components.", diagnostics))
    elif "installed_manifest" in stale:
        checks.append(version_check.warn("Installed manifest settings metadata is stale, but live runtime is current.", "Run Repair Background Monitor or Repair Settings Sync to rebuild installed manifest metadata.", diagnostics))
    else:
        checks.append(version_check.passed("Settings versions are aligned.", diagnostics))

    notifier_check = FunctionalCheck(
        "settings.notifier_status_consistency",
        "Settings",
        "user notifier status consistency",
        "Live user notifier status does not conflict with installed historical state.",
        "high",
        "settings",
    )
    alert_agent = diagnostics.get("user_alert_agent", {})
    historical = diagnostics.get("historical_installed_state", {})
    conflict = bool(alert_agent.get("running")) and str(historical.get("user_notifier_running", "")) == "0" and diagnostics.get("current_runtime_values", {}).get("user_notifier_status_source") != "live_launchctl_process_plist"
    if conflict:
        checks.append(notifier_check.failed("Stale installed notifier state is being displayed as current truth.", "Use canonical live user notifier status in settings diagnostics.", diagnostics))
    else:
        checks.append(notifier_check.passed("User notifier current status is canonical or stale values are labeled historical.", {"user_alert_agent": alert_agent, "historical_installed_state": historical}))

    manifest_check = FunctionalCheck(
        "settings.installed_manifest_freshness",
        "Settings",
        "installed manifest freshness",
        "Installed monitor manifest freshness is explicit and not treated as runtime truth.",
        "medium",
        "settings",
    )
    if "installed_manifest" in stale:
        checks.append(manifest_check.warn("Installed manifest is stale and labeled separately.", "Run Repair Background Monitor or Rebuild Installed Manifest.", reconciliation))
    else:
        checks.append(manifest_check.passed("Installed manifest settings version is current.", reconciliation))
    return checks
