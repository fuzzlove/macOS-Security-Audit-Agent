# Monitor Settings Audit

Generated for the production Monitor Settings regression audit.

Authoritative settings model: `mac_audit_agent.monitor_settings.MonitorSettings`

Persistent storage: `background_monitor_state.monitor_settings_json`, mirrored to legacy `background_monitor_state` keys by `apply_settings_to_legacy_state()` for runtime/notifier compatibility.

Runtime consumers:
- `NotificationManager.settings()` and alert policy methods consume alerting, notification, and category settings.
- `BackgroundMonitorService` reloads settings in detector loops and suppresses disabled admin/persistence and network collection.
- `LaunchAgentManager` consumes installation settings when generating launchd plists.
- Settings Diagnostics compares model, runtime, notifier, and installed values.

## Visible Monitor Settings Controls

| Name | Widget Type | Tab | Current Value | Default Value | Storage Location | Signal Connected? | Callback Function | Backend Variable | Runtime Consumer | Install Consumer | Working | Reason if broken |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Enable Continuous Monitoring | Checkbox | Monitor Settings | `enabled` state | off until installed | `background_monitor_state.enabled` | Yes | `toggle_continuous_monitoring()` | `enabled`, `running`, `loaded` | LaunchAgent start/stop | launchd loaded state | YES | N/A |
| Start at Login | Checkbox | Monitor Settings | `installed` state | off until selected | launchd plist + `installed` | Yes | `toggle_start_at_login()` | user LaunchAgent installed state | User notifier launchd state | User LaunchAgent | YES | N/A |
| Popup only critical events | Checkbox | Monitor Settings | `alerting.popup_only_severe_events` | true | `monitor_settings_json`, `popup_only_severe_events` | Yes | `apply_monitor_settings_from_ui()` | `popup_only_severe_events` | `NotificationManager` popup policy | N/A | YES | N/A |
| Alert on browser camera-capable processes | Checkbox | Monitor Settings | `alerting.browser_capture_process_popup` | false | `monitor_settings_json`, `browser_capture_process_popup` | Yes | `apply_monitor_settings_from_ui()` | `browser_capture_process_popup` | `NotificationManager` popup policy | N/A | YES | N/A |
| Notify All Events | Checkbox | Monitor Settings | `alerting.notify_all_events` | false | `monitor_settings_json`, `notify_all_events` | Yes | `apply_monitor_settings_from_ui()` | `notify_all_events` | `NotificationManager.should_notify()` | N/A | YES | N/A |
| Notify Important Events | Checkbox | Monitor Settings | `alerting.notify_important_events` | true | `monitor_settings_json`, `notify_important_events` | Yes | `apply_monitor_settings_from_ui()` | `notify_important_events` | `NotificationManager.should_notify()` | N/A | YES | N/A |
| Notify Min Severity | ComboBox | Monitor Settings | `alerting.notify_min_severity` | info | `monitor_settings_json`, `notify_min_severity` | Yes | `apply_monitor_settings_from_ui()` | `notify_min_severity` | `NotificationManager.should_notify()` severity threshold | N/A | YES | N/A |
| Duplicate Rate Limit Seconds | LineEdit | Monitor Settings | `notification.duplicate_rate_limit_seconds` | 10 | `monitor_settings_json`, `duplicate_rate_limit_seconds` | Yes | `apply_monitor_settings_from_ui()` | `duplicate_rate_limit_seconds` | notifier duplicate suppression | N/A | YES | N/A |
| Notification Mode | ComboBox | Monitor Settings | `notification.notification_mode` | overlay | `monitor_settings_json`, `notification_mode`, `high_priority_alert_style` | Yes | `_notification_mode_changed_from_ui()` | `notification_mode` | alert delivery policy | N/A | YES | Fixed: overlay-only no longer saves as `none`. |
| Notification Sound | LineEdit | Monitor Settings | `notification.notification_sound` | Glass | `monitor_settings_json`, `notification_sound` | Yes | `apply_monitor_settings_from_ui()` | `notification_sound` | notifier sound policy | N/A | YES | N/A |
| Save Notification Settings | Button | Monitor Settings | current model | N/A | canonical settings save | Yes | `save_notification_settings()` | all visible monitor settings | runtime/notifier refresh | N/A | YES | N/A |
| Show Bottom-Right Alerts | Checkbox | Monitor Settings | `notification.bottom_right_alerts` | true | `monitor_settings_json`, `show_visible_alerts` | Yes | `apply_monitor_settings_from_ui()` | `show_visible_alerts` | `AlertOverlayManager`/visible-alert policy | N/A | YES | Fixed: bottom-right-only maps to `notification_mode=overlay`. |
| Monitor Network Activity | Checkbox | Monitor Settings | `event_categories.network_activity_monitoring_enabled` | true | `monitor_settings_json`, `network_activity_monitoring_enabled` | Yes | `apply_monitor_settings_from_ui()` | `network_activity_monitoring_enabled` | network detector loop and alert policy | installed manifest state | YES | N/A |
| Monitor Admin and Persistence Changes | Checkbox | Monitor Settings | `event_categories.admin_persistence_monitoring_enabled` | true | `monitor_settings_json`, `admin_persistence_monitoring_enabled` | Yes | `apply_monitor_settings_from_ui()` | `admin_persistence_monitoring_enabled` | admin/persistence detector loop and alert policy | installed manifest state | YES | N/A |
| Idle Warning Minutes | LineEdit | Monitor Settings | `performance.idle_warning_minutes` | 2 | `monitor_settings_json`, `idle_activity_warning_minutes` | Yes | `apply_monitor_settings_from_ui()` | `idle_activity_warning_minutes` | session/idle warning policy | N/A | YES | N/A |
| CFAA Idle Warning | Checkbox | Monitor Settings | `notification.authorized_use_warning` | true | `monitor_settings_json`, `cfaa_idle_warning_enabled` | Yes | `apply_monitor_settings_from_ui()` | `cfaa_idle_warning_enabled` | authorized-use warning policy | N/A | YES | N/A |
| Category Cooldown Seconds | LineEdit | Monitor Settings | `notification.cooldown_seconds` | 600 | `monitor_settings_json`, `cooldown_seconds_per_category` | Yes | `apply_monitor_settings_from_ui()` | `cooldown_seconds_per_category` | visible alert cooldown | N/A | YES | N/A |
| Dialogs | Checkbox | Monitor Settings | `notification.dialogs` | false | `monitor_settings_json`, `notification_mode` | Yes | `apply_monitor_settings_from_ui()` | `notification_mode` | dialog alert policy | N/A | YES | N/A |
| Notification Center | Checkbox | Monitor Settings | `notification.notification_center` | false | `monitor_settings_json`, `notification_mode` | Yes | `apply_monitor_settings_from_ui()` | `notification_mode` | macOS notification fallback policy | N/A | YES | N/A |
| Persistent Alerts | Checkbox | Monitor Settings | `notification.persistent_alerts` | true | `monitor_settings_json`, `persistent_alerts` | Yes | `apply_monitor_settings_from_ui()` | `persistent_alerts` | critical/high visible alert persistence | N/A | YES | N/A |
| Alert Sounds | Checkbox | Monitor Settings | `notification.enable_alert_sounds` | false | `monitor_settings_json`, `enable_alert_sounds` | Yes | `apply_monitor_settings_from_ui()` | `enable_alert_sounds` | notifier sound policy | N/A | YES | N/A |
| Authorized Use Warning | Checkbox | Monitor Settings | `notification.authorized_use_warning` | true | `monitor_settings_json`, `cfaa_idle_warning_enabled` | Yes | `apply_monitor_settings_from_ui()` | `cfaa_idle_warning_enabled` | idle/session warning policy | N/A | YES | N/A |
| Critical Overlay | Checkbox | Monitor Settings | `notification.critical_overlay` | true | `monitor_settings_json`, `critical_overlay_enabled` | Yes | `apply_monitor_settings_from_ui()` | `critical_overlay_enabled` | critical visible-alert policy | N/A | YES | N/A |
| USB | Checkbox | Monitor Settings | `event_categories.usb` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `usb` | USB alert policy | N/A | YES | N/A |
| Bluetooth | Checkbox | Monitor Settings | `event_categories.bluetooth` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `bluetooth` | Bluetooth alert policy | N/A | YES | N/A |
| Camera | Checkbox | Monitor Settings | `event_categories.camera` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `camera` | camera/privacy alert policy | N/A | YES | N/A |
| Lid | Checkbox | Monitor Settings | `event_categories.lid` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `lid` | lid/session alert policy | N/A | YES | N/A |
| Session | Checkbox | Monitor Settings | `event_categories.session` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `session` | session alert policy | N/A | YES | N/A |
| Mouse | Checkbox | Monitor Settings | `event_categories.mouse` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `mouse` | HID/session alert policy | N/A | YES | N/A |
| Keyboard | Checkbox | Monitor Settings | `event_categories.keyboard` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `keyboard` | HID/session alert policy | N/A | YES | N/A |
| Trackpad | Checkbox | Monitor Settings | `event_categories.trackpad` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `trackpad` | HID/session alert policy | N/A | YES | N/A |
| Network | Checkbox | Monitor Settings | `event_categories.network` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `network` | network alert policy; disabled when parent off | N/A | YES | N/A |
| Persistence | Checkbox | Monitor Settings | `event_categories.persistence` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `persistence` | persistence alert policy; disabled when parent off | N/A | YES | N/A |
| Admin | Checkbox | Monitor Settings | `event_categories.admin` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `admin` | admin alert policy; disabled when parent off | N/A | YES | N/A |
| Apple Exposure | Checkbox | Monitor Settings | `event_categories.apple_exposure` | true | `monitor_settings_json`, `show_apple_forecast_alerts` | Yes | `apply_monitor_settings_from_ui()` | `apple_exposure.enabled` | Apple exposure alert policy | N/A | YES | N/A |
| Monitor Health | Checkbox | Monitor Settings | `event_categories.monitor_health` | true | `monitor_settings_json`, `event_preferences_json` | Yes | `apply_monitor_settings_from_ui()` | `monitor_health` | monitor integrity/health alert policy | N/A | YES | N/A |
| Monitor Mode | ComboBox | Monitor Settings | `installation.monitor_mode` | user | `monitor_settings_json`, `monitor_mode`, `monitor_install_mode` | Yes | `_installation_mode_changed_from_ui()` | `installation.monitor_mode` | runtime mode diagnostics | launchd install target | YES | Added canonical control. |
| User LaunchAgent | Checkbox | Monitor Settings | `installation.user_launch_agent` | true | `monitor_settings_json`, `installation_user_launch_agent` | Yes | `apply_monitor_settings_from_ui()` | `installation.user_launch_agent` | diagnostics | user LaunchAgent install | YES | Added canonical control. |
| System LaunchDaemon | Checkbox | Monitor Settings | `installation.system_launch_daemon` | false | `monitor_settings_json`, `installation_system_launch_daemon` | Yes | `apply_monitor_settings_from_ui()` | `installation.system_launch_daemon` | diagnostics | system LaunchDaemon install | YES | Added canonical control. |
| Notifier | Checkbox | Monitor Settings | `installation.notifier` | true | `monitor_settings_json`, `installation_notifier` | Yes | `apply_monitor_settings_from_ui()` | `installation.notifier` | notifier diagnostics | user notifier install companion | YES | Added canonical control. |
| RunAtLoad | Checkbox | Monitor Settings | `installation.run_at_load` | true | `monitor_settings_json`, `installation_run_at_load` | Yes | `apply_monitor_settings_from_ui()` | `installation.run_at_load` | diagnostics | launchd `RunAtLoad` | YES | Added launchd consumer. |
| KeepAlive | Checkbox | Monitor Settings | `installation.keep_alive` | true | `monitor_settings_json`, `installation_keep_alive` | Yes | `apply_monitor_settings_from_ui()` | `installation.keep_alive` | diagnostics | launchd `KeepAlive` | YES | Added launchd consumer. |
| Auto Restart | Checkbox | Monitor Settings | `installation.auto_restart` | true | `monitor_settings_json`, `installation_auto_restart` | Yes | `apply_monitor_settings_from_ui()` | `installation.auto_restart` | diagnostics | launchd `KeepAlive` generation | YES | Added launchd consumer. |
| DB Path | LineEdit | Monitor Settings | `installation.db_path` | active audit DB path | `monitor_settings_json`, `db_path` | Yes | `apply_monitor_settings_from_ui()` | `installation.db_path` | runtime DB diagnostics | launchd `MAC_AUDIT_AGENT_DB_PATH` | YES | Added launchd consumer. |
| Log Path | LineEdit | Monitor Settings | `installation.log_path` | fallback monitor log path | `monitor_settings_json`, `log_path` | Yes | `apply_monitor_settings_from_ui()` | `installation.log_path` | diagnostics/log links | launchd stdout/stderr paths | YES | Added launchd consumer. |
| Apply Settings | Button | Monitor Settings | current model | N/A | canonical save | Yes | `apply_monitor_settings_from_ui()` | all settings | runtime/notifier refresh | N/A | YES | Added diagnostics action. |
| Apply and Restart Monitor | Button | Monitor Settings | current model | N/A | canonical save | Yes | `apply_settings_and_restart_monitor()` | all settings | runtime restart | launchd loaded service | YES | Added diagnostics action. |
| Reinstall Monitor With Current Settings | Button | Monitor Settings | current model | N/A | canonical save | Yes | `reinstall_monitor_with_current_settings()` | all installation settings | runtime after reinstall | launchd plist generation | YES | Added diagnostics action. |
| Repair Settings Mismatch | Button | Monitor Settings | diagnostics mismatch state | disabled unless mismatch | canonical save + diagnostics | Yes | `repair_settings_mismatch()` | all settings | runtime/notifier reapply | reinstall guidance for install settings | YES | N/A |

## Hidden or Removed Controls

The legacy aggregate controls `Physical/Session`, `USB/Bluetooth`, and `Apple Forecast` remain hidden and are not user-facing settings. Their old storage keys are still written as compatibility mirrors from canonical event category settings.

Developer/test controls remain hidden unless Developer Mode is enabled. They are not part of the production Monitor Settings surface.

## Fixed Findings

- Fixed bottom-right-only alerts saving as `notification_mode=none`.
- Fixed inconsistent notification defaults loaded from JSON; defaults now match overlay-only delivery.
- Added canonical installation controls for monitor mode, notifier, RunAtLoad, KeepAlive, Auto Restart, DB path, and log path.
- Connected installation settings to actual launchd plist generation.
- Added installed-settings recording for mismatch diagnostics.
- Added diagnostics action buttons for apply, apply-and-restart, and reinstall-with-current-settings.
- Fixed USB/Bluetooth monitoring enforcement so Monitor USB Devices and Monitor Bluetooth Devices persist to canonical settings, control daemon polling and USB observer behavior, suppress stale notifier alerts with explicit reasons, and show disabled-by-settings diagnostics.
- Fixed system-daemon settings propagation when UI and daemon use separate databases, and discard queued USB observer events when USB monitoring is disabled so stale USB events cannot emit after re-enable.
- Reinstated four production monitoring parents (USB, Bluetooth, Network Activity, Admin/Persistence), added child controls for USB/Bluetooth/Network/Admin-Persistence alert categories, preserved child values while parents are disabled, and added numeric `settings_version` plus UTC `updated_at` for daemon/notifier drift detection.
