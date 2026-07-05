# Alert Pipeline Audit

Project: macOS Security Audit Agent / MSAA

Audit date: 2026-06-28

Authoritative alert renderer: `AlertOverlayManager` behavior implemented through `NotificationManager.show_visible_security_alert()` and `security_overlay.py`.

## Pipeline

Detector -> Canonical Event Normalizer -> Event Database -> Severity Engine -> Alert Policy Engine -> Rate Limiter -> User Notifier -> AlertOverlayManager -> Bottom-right UI render

## Stage Audit

| Stage | Input Received | Output Produced | Event ID | Event Type | Canonical Event Type | Severity | Policy Decision | Suppression Reason | Rate Limiter Decision | Notifier Received | Overlay Render Attempted | Overlay Render Success | Last Error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Detector | Yes when detector enabled | `BackgroundMonitorEvent` | `event.event_id` | `event.event_type` | Pending normalization | Detector supplied | Pending | Pending | Pending | No | No | No | Detector exception stored in `detector_errors_json` |
| Canonical Event Normalizer | Yes | `canonical_event_type()` result | Same | Original in trace | `normalized_event_type` / `canonical_event_type` | Same | Pending | Pending | Pending | No | No | No | Normalization failure is recorded in event trace when present |
| Event Database | Yes | Stored monitor event | Same | Canonical | Canonical | Same or policy-upgraded | Pending | DB failure if write fails | Pending | No | No | No | `last_error=db write failed...` |
| Severity Engine | Yes | Effective severity | Same | Canonical | Canonical | `severity_after_policy` | Pending | Pending | Pending | No | No | No | Invalid severity normalizes to `info` |
| Alert Policy Engine | Yes | Allow/suppress decision | Same | Canonical | Canonical | Effective | `notification_policy_result` | `alert_suppression_reason` | Pending | Maybe | Maybe | Maybe | Policy errors are written to alert trace |
| Rate Limiter | Yes for allowed alert candidates | Allow/group/cooldown | Same | Canonical | Canonical | Effective | Allow/group/cooldown | `within_cooldown` or grouped reason | `cooldown_result` / `rate_limiter_result` | Yes in notifier mode | Maybe | Maybe | Queue errors recorded in trace |
| User Notifier | Yes when notifier sees DB event | Overlay dispatch or explicit suppression | Same | Canonical | Canonical | Effective | Allow/suppress | Explicit setting/cooldown reason | Same | `notifier_received` | Maybe | Maybe | Notifier errors in `last_notification_error` |
| AlertOverlayManager | Yes when overlay required | State payload for overlay process | Same | Canonical | Canonical | Effective | Allow | None or render failure | N/A | Yes | `overlay_render_attempted` | `overlay_render_success` | `render_error` |
| Bottom-right UI Render | Overlay state payload | Visible card bottom-right | Same | Canonical | Canonical | Effective | Display | None | N/A | Yes | Yes | Yes/No | Overlay process/state errors |

## AlertDeliveryTrace Model

`AlertDeliveryTrace` is an alias of `EventAlertTrace` with production field aliases:

- `trace_id`
- `event_id`
- `event_type`
- `canonical_event_type`
- `severity`
- `created_at`
- `detector_source`
- `event_written_to_db`
- `event_db_path`
- `notifier_received`
- `notifier_settings_version`
- `daemon_settings_version`
- `policy_result`
- `suppression_reason`
- `rate_limiter_result`
- `overlay_render_attempted`
- `overlay_render_success`
- `overlay_window_id`
- `render_error`
- `displayed_at`
- `acknowledged_at`

## Required Suppression Reasons

- `persistent_local_edr_disabled`
- `persistent_local_edr_alerts_disabled`
- `bottom_right_alerts_disabled`
- `usb_monitoring_disabled`
- `bluetooth_monitoring_disabled`
- `network_activity_monitoring_disabled`
- `admin_persistence_monitoring_disabled`
- `below_min_severity`
- `within_cooldown`
- child setting reasons such as `usb_new_device_alerts_disabled`

## Missing Alert Troubleshooting

If an event is logged but no alert appears, inspect:

1. Latest `EventAlertTrace` / `AlertDeliveryTrace`.
2. `notification_policy_result`.
3. `alert_suppression_reason`.
4. `cooldown_result`.
5. `overlay_dispatch_result`.
6. `overlay_error` / `render_error`.
7. Monitor Settings Diagnostics for daemon/notifier settings drift.

No stage should silently drop an alert-worthy event. The expected outcome is either an overlay render attempt or a stored suppression reason.
