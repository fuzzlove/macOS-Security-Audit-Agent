# Persistent EDR Local Settings Audit

Project: macOS Security Audit Agent / MSAA

Audit date: 2026-06-28

Canonical model: `MonitorSettings.local_edr` in `mac_audit_agent/monitor_settings.py`

Canonical persisted payload: `monitor_settings_json` in the background monitor database. Runtime compatibility keys are written by `apply_settings_to_legacy_state()`.

## Settings Path

Required path:

UI -> `MonitorSettings` -> `monitor_settings_json` -> daemon runtime -> notifier runtime -> alert policy -> `AlertOverlayManager` -> bottom-right visible alert

Current implementation:

- UI: `BackgroundMonitorPanel`
- Settings model: `MonitorSettings.local_edr`
- Storage manager: `load_settings()`, `save_settings()`, `validate_settings()`, `migrate_settings()`, `reset_defaults()`, `export_settings()`, `import_settings()`
- Daemon consumer: `BackgroundMonitorService._persistent_local_edr_enabled()`
- Notifier consumer: `NotificationManager.settings()` and `_monitoring_disabled_reason()`
- Alert policy trace: `EventAlertTrace` / `AlertDeliveryTrace`
- Renderer: `NotificationManager.show_visible_security_alert()` -> `security_overlay.py`

## Audited Settings

| Setting | UI Label | Widget Type | Default | Storage Key | Settings File Path | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Install Manifest Consumer | Visible In Diagnostics | Working | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `persistent_local_edr_enabled` | Enable Persistent Local EDR Monitor | Checkbox | `true` | `local_edr.persistent_local_edr_enabled`; legacy `persistent_local_edr_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes, suppresses with `persistent_local_edr_disabled` | Yes | Yes | Yes | Parent control now disables detector loops without deleting child settings. |
| `persistent_local_edr_mode` | Monitor Mode | Combo box | `user_agent` | `local_edr.persistent_local_edr_mode`; legacy `persistent_local_edr_mode` | `monitor_settings_json` | Yes | Yes | Yes, through install/runtime mode | Indirect | No direct alert effect | Yes | Yes | Yes | Derived from selected LaunchAgent/LaunchDaemon/protected mode. |
| `persistent_local_edr_alerts_enabled` | Enable bottom-right security alerts | Checkbox | `true` | `local_edr.persistent_local_edr_alerts_enabled`; legacy `persistent_local_edr_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes, suppresses with `persistent_local_edr_alerts_disabled` | Yes | Yes | Yes | Mirrors bottom-right overlay alert enablement. |
| `persistent_local_edr_local_only` | Local-only telemetry/privacy mode | Stored setting | `true` | `local_edr.persistent_local_edr_local_only`; legacy `persistent_local_edr_local_only` | `monitor_settings_json` | Yes | Yes | Indirect | Indirect | No direct alert effect | No | Yes | Yes | MSAA export/reporting remains explicit user action. |
| `bottom_right_alerts` | Enable bottom-right security alerts | Checkbox | `true` | `notification.bottom_right_alerts`; legacy `show_visible_alerts` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes, suppresses with `bottom_right_alerts_disabled` | Indirect | Yes | Yes | Routes to AlertOverlayManager by default. |
| `notify_min_severity` | Notify Min Severity | Combo box | `info` | `alerting.notify_min_severity`; legacy `notify_min_severity` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes, lower severities are log-only with explicit reason | No | Yes | Yes | Critical/high/medium filtering follows severity rank. |
| `usb_monitoring_enabled` | Monitor USB Devices | Checkbox | `true` | `event_categories.usb_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Disabled USB is not treated as detector failure. |
| `bluetooth_monitoring_enabled` | Monitor Bluetooth Devices | Checkbox | `true` | `event_categories.bluetooth_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Disabled Bluetooth is not treated as detector failure. |
| `network_activity_monitoring_enabled` | Monitor Network Activity | Checkbox | `true` | `event_categories.network_activity_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Disabled Network is not treated as detector failure. |
| `admin_persistence_monitoring_enabled` | Monitor Admin and Persistence Changes | Checkbox | `true` | `event_categories.admin_persistence_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Disabled Admin/Persistence is not treated as detector failure. |
| `apple_exposure` | Monitor Apple Exposure status | Checkbox | `true` | `event_categories.apple_exposure` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | No | Yes | Yes | Child of Persistent Local EDR UI behavior. |
| `monitor_health` | Monitor health / tamper detection | Checkbox | `true` | `event_categories.monitor_health` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | No | Yes | Yes | Child of Persistent Local EDR UI behavior. |

## Enforcement Summary

- When `persistent_local_edr_enabled=false`, daemon detector cycles are skipped.
- The daemon writes `Persistent Local EDR disabled by settings.` and sets detector flags to disabled.
- The notifier suppresses monitor alert categories with `persistent_local_edr_disabled`.
- Bottom-right overlay suppression uses `bottom_right_alerts_disabled` when overlay alerts are disabled.
- Child controls remain saved while the Persistent Local EDR parent is disabled.
- Historical events remain visible.

## Diagnostics

Monitor Settings Diagnostics now include:

- UI/settings value
- daemon runtime value
- notifier value
- settings version
- notifier settings version
- daemon settings version
- last daemon reload
- last suppression reason
- install-manifest value
- mismatch list and repair recommendation

## Broken Items Found And Fixed

- Missing canonical Persistent Local EDR setting: fixed with `MonitorSettings.local_edr`.
- Ambiguous continuous monitoring checkbox: fixed with explicit `Enable Persistent Local EDR Monitor`.
- Alert overlay opacity below production floor: fixed in `security_overlay.py`.
- Network runtime diagnostics were thinner than USB/Bluetooth: fixed with explicit network runtime fields.
