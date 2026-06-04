# Alert Regression Analysis

## Symptom

Demo bottom-right alerts worked, but real detector events such as lid, USB, Bluetooth, input-after-idle, network, persistence, and possible compromise evidence did not reliably produce visible alerts.

## Previous Working Function

The working final renderer is:

- `NotificationManager.show_visible_security_alert(...)`
- `NotificationManager._dispatch_visible_alert(...)`
- `mac_audit_agent/security_overlay.py`

The UI demo button already called this path directly, which is why demo alerts continued to appear.

## Current Broken Function

Real events entered through:

1. detector
2. `BackgroundMonitorService.record_monitor_event(...)`
3. SQLite `background_monitor_events`
4. user notifier `process_pending_notifications(...)`
5. `NotificationManager.evaluate_notification_decision(...)`
6. `NotificationManager.notify(...)`

That path still allowed several real events to be treated as log-only, Notification Center-only, or suppressed before they reached the same overlay renderer used by demos.

## Suspected Regression

The regression was a routing and policy mismatch, not an overlay rendering failure:

- Canonical event normalization happened inside notification helpers, after the event had already been preference-checked and stored.
- The mandatory visible event list was scattered across `DEFAULT_EVENT_PREFERENCES`, `CRITICAL_POPUP_ALLOWLIST`, `ACTIVITY_OVERLAY_EVENT_TYPES`, and category sets, so aliases such as `usb_reconnect_detected`, `keyboard_activity_detected`, or `clamshell_open` could miss the visible-alert policy.
- Policy evaluation set `visible_alert_shown=True` before `_dispatch_visible_alert(...)` actually launched the overlay, so cooldown and delivery state could claim success before display success was known.
- Cooldown state could be written even when the overlay process failed to launch.

## Fix Applied

- Canonicalize every event at the detector-to-DB boundary in `BackgroundMonitorService.record_monitor_event(...)`.
- Preserve both `original_event_type` and `normalized_event_type` in `EventAlertTrace`.
- Added a mandatory visible alert registry in `notification_manager.py` for session, input, device, network, persistence, privilege, tamper, monitor-health, and possible compromise evidence.
- Made mandatory visible events default to visible overlay notifications even when their severity is medium/info or no explicit preference exists.
- Routed real events, notifier events, demo events, and the Authorized Use Notice through `show_visible_security_alert(...)`.
- Changed delivery state so `visible_alert_shown`, visible-alert cooldown, and `displayed_at` are set only after overlay dispatch succeeds.
- Added canonical aliases for clamshell, USB reconnect, input activity, Bluetooth inventory/activity, and hidden localhost event names.

## Verification Added

- Real mandatory synthetic event uses the same overlay path as the demo.
- Two pending DB events are consumed and alerted sequentially.
- Keyboard/mouse/trackpad-after-idle aliases render the Authorized Use Notice overlay with the required title, copy, and buttons.

## Remaining Real UAT

The code path is repaired and covered by synthetic tests. Real hardware UAT still has to be run on macOS hardware for:

- USB connect/remove
- Bluetooth connect/disconnect
- lid open/close where supported
- idle for 2 minutes, then mouse/keyboard/trackpad activity
- lock/unlock
- new network connection
- synthetic possible compromise evidence
