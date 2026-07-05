# Physical/Session Settings Audit

Project: macOS Security Audit Agent / MSAA

Audit date: 2026-06-28

Canonical settings source: `MonitorSettings.event_categories` and `MonitorSettings.notification` in `mac_audit_agent/monitor_settings.py`

Canonical persisted payload: `monitor_settings_json` in the background monitor database. Legacy runtime mirror keys are written by `apply_settings_to_legacy_state()`.

## Result

The Settings -> Physical/Session area is now split into:

1. Physical Device Monitoring
2. Physical Session Monitoring

USB and Bluetooth controls are no longer visually mixed into generic session settings. Legacy aggregate compatibility keys remain in storage for migration, but there are no user-facing aggregate checkboxes for physical/session or USB/Bluetooth.

## USB Controls

| UI Label | Widget Type | Parent Section | Current Saved Value | Default Value | Settings Key | Settings File Path | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Monitoring Coverage Consumer | Working | Issue Found | Fix Required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Monitor USB Devices | Checkbox | Physical Device Monitoring | `event_categories.usb_monitoring_enabled` | `true` | `usb_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Previously visually mixed with session settings | Fixed layout and tooltip |
| Alert on new USB devices | Checkbox | Physical Device Alert Details | `event_categories.usb_new_device_alerts_enabled` | `true` | `usb_new_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Child control existed but grouping was unclear | Fixed label/grouping |
| Alert on trusted USB reconnects | Checkbox | Physical Device Alert Details | `event_categories.usb_trusted_device_alerts_enabled` | `true` | `usb_trusted_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on USB HID devices | Checkbox | Physical Device Alert Details | `event_categories.usb_hid_alerts_enabled` | `true` | `usb_hid_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on USB storage devices | Checkbox | Physical Device Alert Details | `event_categories.usb_storage_alerts_enabled` | `true` | `usb_storage_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on USB network adapters | Checkbox | Physical Device Alert Details | `event_categories.usb_network_adapter_alerts_enabled` | `true` | `usb_network_adapter_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on unknown USB devices | Checkbox | Physical Device Alert Details | `event_categories.usb_unknown_device_alerts_enabled` | `true` | `usb_unknown_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Missing in older UI | Added |

## Bluetooth Controls

| UI Label | Widget Type | Parent Section | Current Saved Value | Default Value | Settings Key | Settings File Path | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Monitoring Coverage Consumer | Working | Issue Found | Fix Required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Monitor Bluetooth Devices | Checkbox | Physical Device Monitoring | `event_categories.bluetooth_monitoring_enabled` | `true` | `bluetooth_monitoring_enabled` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes | Yes | USB/Bluetooth grouping unclear; typo risk | Fixed spelling and grouping |
| Alert on new Bluetooth devices | Checkbox | Physical Device Alert Details | `event_categories.bluetooth_new_device_alerts_enabled` | `true` | `bluetooth_new_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on trusted Bluetooth reconnects | Checkbox | Physical Device Alert Details | `event_categories.bluetooth_trusted_device_alerts_enabled` | `true` | `bluetooth_trusted_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on Bluetooth inventory changes | Checkbox | Physical Device Alert Details | `event_categories.bluetooth_inventory_alerts_enabled` | `true` | `bluetooth_inventory_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Grouping was unclear | Fixed label/grouping |
| Alert on unknown Bluetooth devices | Checkbox | Physical Device Alert Details | `event_categories.bluetooth_unknown_device_alerts_enabled` | `true` | `bluetooth_unknown_device_alerts_enabled` | `monitor_settings_json` | Yes | Yes | Indirect | Yes | Yes | N/A | Yes | Missing in older UI | Added |

## Session Controls

| UI Label | Widget Type | Parent Section | Current Saved Value | Default Value | Settings Key | Settings File Path | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Monitoring Coverage Consumer | Working | Issue Found | Fix Required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Monitor lid open/close | Checkbox | Physical Session Monitoring | `event_categories.lid` | `true` | `lid` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes, session detector | Yes | Label was generic | Fixed label |
| Monitor screen lock/unlock | Checkbox | Physical Session Monitoring | `event_categories.session` | `true` | `session` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes, session detector | Yes | Label was generic | Fixed label |
| Monitor idle resume | Checkbox | Physical Session Monitoring | `event_categories.mouse` | `true` | `mouse` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes, input/idle detector | Yes | Label was generic | Fixed label |
| Monitor input activity after idle | Checkbox | Physical Session Monitoring | `event_categories.keyboard` | `true` | `keyboard` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes, input/idle detector | Yes | Label was generic | Fixed label |
| Monitor trackpad activity after idle | Checkbox | Physical Session Monitoring | `event_categories.trackpad` | `true` | `trackpad` | `monitor_settings_json` | Yes | Yes | Yes | Yes | Yes | Yes, input/idle detector | Yes | Label was generic | Fixed label |
| Enable Authorized Use warning | Checkbox | Physical Session Monitoring | `notification.authorized_use_warning` | `true` | `authorized_use_warning`; legacy `cfaa_idle_warning_enabled` | `monitor_settings_json` | Yes | Yes | N/A | Yes | Yes | N/A | Yes | Was separated from session group visually | Still visible near session controls and persisted |

## Parent / Child Behavior

- Persistent Local EDR disabled: child controls are disabled with `Disabled because Persistent Local EDR Monitor is turned off.`
- USB disabled: USB child alert controls are disabled and saved values are preserved.
- Bluetooth disabled: Bluetooth child alert controls are disabled and saved values are preserved.
- Child controls show a disabled tooltip instead of silently greying out.
- Parent re-enabled restores previous child values.

## Spelling Audit

- No misspelled Bluetooth label remains in the audited UI.
- User-facing label is `Bluetooth`.

## Enforcement Summary

- USB and Bluetooth parent controls affect daemon detector/native observer execution.
- Session controls affect notification policy/category preferences and session event visibility.
- Alert policy writes explicit suppression reasons.
- Monitoring Coverage distinguishes disabled settings from failures.
