# Monitor Settings Audit

Date: 2026-06-27

Scope: `mac_audit_agent/ui/background_monitor_panel.py`, `mac_audit_agent/monitor_settings.py`, `mac_audit_agent/notification_manager.py`, `mac_audit_agent/monitor.py`, `mac_audit_agent/launch_agent.py`, and SQLite `background_monitor_state`.

Canonical settings location: `background_monitor_state.monitor_settings_json`

Legacy compatibility keys are still written by `apply_settings_to_legacy_state()` because the runtime monitor and notifier already consume those keys. The canonical model is the source of truth; legacy keys are runtime projections.

## Summary

The previous panel exposed several coarse settings that were saved as scattered state keys and did not map cleanly to independent event categories. The repaired implementation creates one `MonitorSettings` model and applies it to UI, storage, notifier policy, runtime policy, and diagnostics.

Old broad category controls are hidden:

- Physical/Session
- USB/Bluetooth
- Network
- Admin/Persistence
- Apple Forecast

They were replaced with independent controls for USB, Bluetooth, Camera, Lid, Session, Mouse, Keyboard, Trackpad, Network, Persistence, Admin, Apple Exposure, and Monitor Health.

## Settings Inventory

| Name | Widget Type | Tab | Current Value | Default Value | Storage Location | Signal Connected? | Callback Function | Backend Variable | Runtime Consumer | Install Consumer | Working | Reason if broken |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Enable Continuous Monitoring | QCheckBox | Monitor Settings | runtime status | off until installed/running | `background_monitor_state.enabled/running/loaded` | yes | `toggle_continuous_monitoring` | launchd loaded/running state | `LaunchAgentManager.start/stop` | user LaunchAgent or system LaunchDaemon | YES |  |
| Start at Login | QCheckBox | Monitor Settings | launchd installed state | off | `background_monitor_state.installed/enabled` | yes | `toggle_start_at_login` | user notifier LaunchAgent | user notifier runtime | user LaunchAgent install/uninstall | YES |  |
| Popup only critical events | QCheckBox | Monitor Settings | `MonitorSettings.alerting.popup_only_severe_events` | true | `monitor_settings_json`, projected to `popup_only_severe_events` | yes | `apply_monitor_settings_from_ui` | `popup_only_severe_events` | `NotificationManager.should_popup` | none | YES |  |
| Alert on browser camera-capable processes | QCheckBox | Monitor Settings | `MonitorSettings.alerting.browser_capture_process_popup` | false | `monitor_settings_json`, projected to `browser_capture_process_popup` | yes | `apply_monitor_settings_from_ui` | `browser_capture_process_popup` | `NotificationManager.should_popup`, `should_show_visible_alert` | none | YES |  |
| Notify All Events | QCheckBox | Monitor Settings | `MonitorSettings.alerting.notify_all_events` | false | `monitor_settings_json`, projected to `notify_all_events` | yes | `apply_monitor_settings_from_ui` | `notify_all_events` | `NotificationManager.evaluate_notification_decision` | none | YES |  |
| Notify Important Events | QCheckBox | Monitor Settings | `MonitorSettings.alerting.notify_important_events` | true | `monitor_settings_json`, projected to `notify_important_events` | yes | `apply_monitor_settings_from_ui` | `notify_important_events` | `NotificationManager.evaluate_notification_decision` | none | YES |  |
| Notify Min Severity | QComboBox | Monitor Settings | `MonitorSettings.alerting.notify_min_severity` | info | `monitor_settings_json`, projected to `notify_min_severity` | yes | `apply_monitor_settings_from_ui` | `notify_min_severity` | `NotificationManager.evaluate_notification_decision` | none | YES | Severity threshold now applies to default preferences; lower severities no longer bypass the selector. |
| Duplicate Rate Limit Seconds | QLineEdit | Monitor Settings | `MonitorSettings.notification.duplicate_rate_limit_seconds` | 10 | `monitor_settings_json`, projected to `duplicate_rate_limit_seconds` | yes | `apply_monitor_settings_from_ui` | `duplicate_rate_limit_seconds` | `NotificationManager.evaluate_notification_decision` | none | YES |  |
| Notification Mode | QComboBox | Monitor Settings | `MonitorSettings.notification.notification_mode` | notification | `monitor_settings_json`, projected to `notification_mode` and `high_priority_alert_style` | yes | `apply_monitor_settings_from_ui` | `notification_mode` | `NotificationManager.notify` | none | YES |  |
| Notification Sound | QLineEdit | Monitor Settings | `MonitorSettings.notification.notification_sound` | Glass | `monitor_settings_json`, projected to `notification_sound` | yes | `apply_monitor_settings_from_ui` | `notification_sound` | `NotificationManager.notify` | none | YES |  |
| Show Bottom-Right Alerts | QCheckBox | Monitor Settings | `MonitorSettings.notification.bottom_right_alerts` | true | `monitor_settings_json`, projected to `show_visible_alerts` | yes | `apply_monitor_settings_from_ui` | `show_visible_alerts` | `NotificationManager.should_show_visible_alert` | none | YES |  |
| Dialogs | QCheckBox | Monitor Settings | derived from `MonitorSettings.notification.notification_mode` | false for notification mode | `monitor_settings_json`, projected to `notification_mode` | yes | `apply_monitor_settings_from_ui` | `notification_mode` | `NotificationManager.notify` | none | YES |  |
| Notification Center | QCheckBox | Monitor Settings | derived from `MonitorSettings.notification.notification_mode` | true | `monitor_settings_json`, projected to `notification_mode` | yes | `apply_monitor_settings_from_ui` | `notification_mode` | `NotificationManager.notify` | none | YES |  |
| Persistent Alerts | QCheckBox | Monitor Settings | `MonitorSettings.notification.persistent_alerts` | true | `monitor_settings_json` | yes | `apply_monitor_settings_from_ui` | `persistent_alerts` | visible alert diagnostics/model | none | YES | Stored and diagnosed. Current overlay persistence is always-on for active alerts. |
| Authorized Use Warning | QCheckBox | Monitor Settings | `MonitorSettings.notification.authorized_use_warning` | true | `monitor_settings_json`, projected to `cfaa_idle_warning_enabled` | yes | `apply_monitor_settings_from_ui` | `cfaa_idle_warning_enabled` | `NotificationManager.should_show_visible_alert`, `notify_cfaa_idle_reminder` | none | YES |  |
| Critical Overlay | QCheckBox | Monitor Settings | `MonitorSettings.notification.critical_overlay` | true | `monitor_settings_json` | yes | `apply_monitor_settings_from_ui` | `critical_overlay` | diagnostics/model; bottom-right alert controls actual overlay | none | YES | Stored and diagnosed. Critical overlay display is also governed by Bottom-Right Alerts and severity policy. |
| Idle Warning Minutes | QLineEdit | Monitor Settings | `MonitorSettings.performance.idle_warning_minutes` | 2 | `monitor_settings_json`, projected to `idle_activity_warning_minutes` | yes | `apply_monitor_settings_from_ui` | `idle_activity_warning_minutes` | idle notice runtime policy | none | YES |  |
| CFAA Idle Warning | QCheckBox | Monitor Settings | same as Authorized Use Warning | true | `monitor_settings_json`, projected to `cfaa_idle_warning_enabled` | yes | `apply_monitor_settings_from_ui` | `cfaa_idle_warning_enabled` | `NotificationManager.notify_cfaa_idle_reminder` | none | YES | Kept as an alias for compatibility. |
| Category Cooldown Seconds | QLineEdit | Monitor Settings | `MonitorSettings.notification.cooldown_seconds` | 600 | `monitor_settings_json`, projected to `cooldown_seconds_per_category` | yes | `apply_monitor_settings_from_ui` | `cooldown_seconds_per_category` | `NotificationManager.should_show_visible_alert` | none | YES |  |
| USB | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.usb` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | USB event preference `enabled/notify/notification_mode` | `NotificationManager.preference_for` | none | YES |  |
| Bluetooth | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.bluetooth` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | Bluetooth event preference `enabled/notify/notification_mode` | `NotificationManager.preference_for` | none | YES |  |
| Camera | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.camera` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | camera/microphone/capture event preferences | `NotificationManager.preference_for` | none | YES |  |
| Lid | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.lid` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | lid event preferences | `NotificationManager.preference_for` | none | YES |  |
| Session | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.session` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | session/display event preferences | `NotificationManager.preference_for` | none | YES |  |
| Mouse | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.mouse` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | mouse/input event preferences | `NotificationManager.preference_for` | none | YES |  |
| Keyboard | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.keyboard` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | keyboard/input event preferences | `NotificationManager.preference_for` | none | YES |  |
| Trackpad | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.trackpad` | true | `monitor_settings_json`, projected into `event_preferences_json` | yes | `apply_monitor_settings_from_ui` | trackpad/HID event preferences | `NotificationManager.preference_for` | none | YES |  |
| Network | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.network` | true | `monitor_settings_json`, projected to `show_network_change_alerts` and event preferences | yes | `apply_monitor_settings_from_ui` | network event preferences | `NotificationManager.preference_for` | none | YES |  |
| Persistence | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.persistence` | true | `monitor_settings_json`, projected to event preferences | yes | `apply_monitor_settings_from_ui` | persistence event preferences | `NotificationManager.preference_for` | none | YES |  |
| Admin | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.admin` | true | `monitor_settings_json`, projected to event preferences | yes | `apply_monitor_settings_from_ui` | admin event preferences | `NotificationManager.preference_for` | none | YES |  |
| Apple Exposure | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.apple_exposure` | true | `monitor_settings_json`, projected to `show_apple_forecast_alerts` and event preferences | yes | `apply_monitor_settings_from_ui` | advisory event preferences | `NotificationManager.preference_for` | none | YES |  |
| Monitor Health | QCheckBox | Monitor Settings > Event Categories | `MonitorSettings.event_categories.monitor_health` | true | `monitor_settings_json`, projected to event preferences | yes | `apply_monitor_settings_from_ui` | monitor health event preferences | `NotificationManager.preference_for` | none | YES |  |
| Emergency Lockdown Policy | QComboBox | Security Response > Emergency Lockdown | `emergency_lockdown_policy_json` | Recommend Only | emergency lockdown policy state keys | yes | `save_emergency_lockdown_policy` | lockdown policy | `enable_lockdown_with_user_policy` | none | YES |  |
| Require admin approval if needed | QCheckBox | Security Response > Emergency Lockdown | policy value | true | emergency lockdown policy state keys | yes | `save_emergency_lockdown_policy` | `require_admin_approval` | emergency lockdown workflow | none | YES |  |
| Typed confirmation | QLineEdit | Security Response > Emergency Lockdown | policy value | empty | emergency lockdown policy state keys | yes | `save_emergency_lockdown_policy` | confirmation string | emergency lockdown workflow | none | YES |  |
| Settings Diagnostics | QTextEdit | Monitor Settings | diagnostics JSON | generated | state and runtime inspection | read-only | `_refresh_settings_diagnostics` | diagnostics payload | analyst validation | install mismatch detection | YES |  |
| Repair Settings Mismatch | QPushButton | Monitor Settings | enabled on mismatch | disabled | N/A | yes | `repair_settings_mismatch` | canonical settings reapplied | runtime state projection | tells user when reinstall/admin repair is required | YES |  |

## Installation Controls

System installation choices are implemented as actions rather than silent settings toggles:

- `Install System Monitor + User Notifier` calls `install_system_monitor()`.
- `Install System Monitor` calls `install_system_monitor()`.
- `Install User Notifier` calls `install_user_notifier()`.
- `Install Protected Mode` calls `install_protected_mode()`.
- `Repair Background Monitor`, `Repair System Monitor`, and `Repair Settings Mismatch` explicitly show repair/reinstall requirements.

RunAtLoad and KeepAlive are generated by `LaunchAgentManager` plist creation. They are represented in `MonitorSettings.installation` for diagnostics, but are not exposed as cosmetic UI toggles because changing them requires reinstalling the LaunchAgent/LaunchDaemon.

## Bugs Fixed

1. Severity selector bug:
   Default event preferences could bypass `notify_min_severity`. A Critical threshold now suppresses high/medium/low/info events.

2. Category disable bug:
   Mandatory visible event promotion could override disabled category preferences. Explicit disabled event preferences now win before mandatory promotion.

3. Settings source bug:
   Monitor settings now load from `monitor_settings_json`, recover corrupt JSON safely, project to legacy runtime keys, and expose diagnostics.

4. Coarse category controls:
   Broad visible controls were hidden and replaced with independent category controls.

## Remaining Operational Constraint

System LaunchDaemon and Protected Mode installation require administrator/root approval. The app records intended settings and diagnoses mismatch, but does not silently install privileged components without explicit user/admin action.
