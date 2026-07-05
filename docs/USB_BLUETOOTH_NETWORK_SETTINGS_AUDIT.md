# USB, Bluetooth, and Network Settings Audit

Project: macOS Security Audit Agent / MSAA

Audit date: 2026-06-28

Canonical settings source: `MonitorSettings.event_categories` in `mac_audit_agent/monitor_settings.py`

Canonical settings persistence:
- Primary serialized state: `monitor_settings_json` in the MSAA background monitor database.
- Legacy/runtime projection keys: background monitor state keys written by `save_settings()` / `apply_settings_to_legacy_state()`.
- Runtime reload: `BackgroundMonitorService._update_runtime_state()` reloads `MonitorSettings` at detector-cycle boundaries and records `settings_version`.

Result: USB, Bluetooth, and Network parent controls are production controls. Child controls are alert-policy controls; parent-disabled state suppresses all child behavior without erasing saved child values.

## USB Settings

| Setting | UI Label | Widget Type | Default | Storage Key | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Coverage Consumer | Working | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `usb_monitoring_enabled` | Monitor USB Devices | Checkbox | `true` | `event_categories.usb_monitoring_enabled`; legacy `usb_monitoring_enabled` | Yes | Yes | Yes, skips USB detector/native observer when false | Yes | Yes, suppresses USB alerts with `usb_monitoring_disabled` | Yes, USB Monitor shows Disabled by settings | Yes | Parent value is authoritative; legacy `usb` is normalized from it. |
| `usb_new_device_alerts_enabled` | New USB devices | Checkbox | `true` | `event_categories.usb_new_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect; detector still logs when parent enabled | Yes | Yes, suppresses `new_usb_device_detected` with `usb_new_device_alerts_disabled` | N/A | Yes | Child value remains saved while USB parent is disabled. |
| `usb_trusted_device_alerts_enabled` | Trusted USB reconnects | Checkbox | `true` | `event_categories.usb_trusted_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `trusted_usb_device_connected` with `usb_trusted_device_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `usb_hid_alerts_enabled` | USB HID devices | Checkbox | `true` | `event_categories.usb_hid_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses USB HID/keyboard/mouse/trackpad alerts with `usb_hid_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `usb_storage_alerts_enabled` | USB storage devices | Checkbox | `true` | `event_categories.usb_storage_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `usb_storage_device_connected` with `usb_storage_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `usb_network_adapter_alerts_enabled` | USB network adapters | Checkbox | `true` | `event_categories.usb_network_adapter_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `usb_network_adapter_connected` with `usb_network_adapter_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `usb_unknown_device_alerts_enabled` | Unknown USB devices | Checkbox | `true` | `event_categories.usb_unknown_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `untrusted_usb_device_connected` and `usb_unknown_class_connected` with `usb_unknown_device_alerts_disabled` | N/A | Yes | Added to close missing unknown-device child control. |

## Bluetooth Settings

| Setting | UI Label | Widget Type | Default | Storage Key | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Coverage Consumer | Working | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bluetooth_monitoring_enabled` | Monitor Bluetooth Devices | Checkbox | `true` | `event_categories.bluetooth_monitoring_enabled`; legacy `bluetooth_monitoring_enabled` | Yes | Yes | Yes, skips Bluetooth detector/native observer when false | Yes | Yes, suppresses Bluetooth alerts with `bluetooth_monitoring_disabled` | Yes, Bluetooth Monitor shows Disabled by settings | Yes | Parent value is authoritative; legacy `bluetooth` is normalized from it. |
| `bluetooth_new_device_alerts_enabled` | New Bluetooth devices | Checkbox | `true` | `event_categories.bluetooth_new_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `bluetooth_device_connected` with `bluetooth_new_device_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `bluetooth_trusted_device_alerts_enabled` | Trusted Bluetooth reconnects | Checkbox | `true` | `event_categories.bluetooth_trusted_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, persisted and exposed for trusted reconnect policy | N/A | Yes | Ready for detector events that distinguish trusted reconnects. |
| `bluetooth_inventory_alerts_enabled` | Bluetooth inventory changes | Checkbox | `true` | `event_categories.bluetooth_inventory_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `bluetooth_inventory_changed` with `bluetooth_inventory_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `bluetooth_unknown_device_alerts_enabled` | Unknown Bluetooth devices | Checkbox | `true` | `event_categories.bluetooth_unknown_device_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses `unknown_bluetooth_device_detected` with `bluetooth_unknown_device_alerts_disabled` | N/A | Yes | Added to close missing unknown-device child control. |

## Network Settings

| Setting | UI Label | Widget Type | Default | Storage Key | Loaded On Startup | Saved On Apply | Daemon Consumer | Notifier Consumer | Alert Policy Consumer | Coverage Consumer | Working | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `network_activity_monitoring_enabled` | Monitor Network Activity | Checkbox | `true` | `event_categories.network_activity_monitoring_enabled`; legacy `network_activity_monitoring_enabled` | Yes | Yes | Yes, skips network detector when false | Yes | Yes, suppresses network alerts with `network_activity_monitoring_disabled` | Yes, Network Activity Monitor shows Disabled by settings | Yes | Parent value is authoritative; legacy `network` is normalized from it. |
| `network_new_connection_alerts_enabled` | New outbound connections | Checkbox | `true` | `event_categories.network_new_connection_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses new connection events with `network_new_connection_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `network_new_listener_alerts_enabled` | New listening ports | Checkbox | `true` | `event_categories.network_new_listener_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses listener-style network events with `network_new_listener_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `network_dns_gateway_alerts_enabled` | DNS/gateway changes | Checkbox | `true` | `event_categories.network_dns_gateway_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses DNS/gateway events with `network_dns_gateway_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `network_vpn_alerts_enabled` | VPN changes | Checkbox | `true` | `event_categories.network_vpn_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses VPN events with `network_vpn_alerts_disabled` | N/A | Yes | Alert-specific child control. |
| `network_suspicious_connection_alerts_enabled` | Suspicious connections | Checkbox | `true` | `event_categories.network_suspicious_connection_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses suspicious connection events with `network_suspicious_connection_alerts_disabled` | N/A | Yes | Added to close missing suspicious-connection child control. |
| `network_localhost_visibility_alerts_enabled` | Localhost visibility mismatches | Checkbox | `true` | `event_categories.network_localhost_visibility_alerts_enabled`; legacy same key | Yes | Yes | Indirect | Yes | Yes, suppresses localhost visibility events with `network_localhost_visibility_alerts_disabled` | N/A | Yes | Added to close missing localhost-visibility child control. |

## Parent / Child Behavior

- Parent unchecked disables child controls in the UI.
- Disabled child controls show: `Disabled because parent monitoring category is off.`
- Child values remain saved while the parent is disabled.
- Parent disabled overrides all child alert behavior.
- Parent re-enabled restores previous child checkbox values.

## Remaining Notes

- Child settings are alert-policy controls, not detector execution controls. Detector execution is controlled by the three parent settings.
- Historical events remain visible after disabling a category.
- Disabled parent states are treated as `Disabled by settings`, not detector failures.
