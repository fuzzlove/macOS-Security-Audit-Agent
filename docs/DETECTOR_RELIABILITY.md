# Detector Reliability

This document describes the current detector stack, the event sources used, the canonical event types they emit or normalize to, and the known failure modes.

## Architecture

The monitor uses four layers:

1. Native event helper bridge
2. Snapshot diff detectors
3. Log fallback detectors
4. Manual UAT/test events

Native helper events, when available, are ingested as JSON Lines and normalized to canonical event types before policy evaluation.
Snapshot diff detectors remain the default path when a helper is unavailable.
Log fallback detectors are used for power/display history when native transitions are not surfaced directly.

## Detector Summary

| Detector | Source method | Canonical event types | Polling interval | Failure modes | SQLite path | Notifier path | Overlay path |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Lid / display / session | `session_monitor.py` snapshot diff, `ioreg`, `pmset`, `CGSession` | `lid_opened`, `lid_closed`, `display_wake`, `display_sleep`, `screen_locked`, `screen_unlocked`, `idle_resume_detected`, `mouse_or_keyboard_activity_after_idle` | ~1s observer + monitor cycle | `ioreg` / `pmset` unavailable, `CGSession` parsing mismatch, stale state | yes | yes | yes |
| USB | `hardware_monitor.py` snapshot diff, `ioreg IOUSBHostDevice` | `usb_device_connected`, `usb_device_removed`, `usb_inventory_changed`, `new_usb_device_detected` | ~1s observer + monitor cycle | `ioreg` output format changes, internal device filtering, dock churn | yes | yes | yes |
| Bluetooth | `hardware_monitor.py` snapshot diff, `ioreg IOBluetoothDevice` | `bluetooth_device_connected`, `bluetooth_device_disconnected`, `bluetooth_inventory_changed` | ~1s observer + monitor cycle | `ioreg` output format changes, device address changes, reconnect churn | yes | yes | yes |
| Input idle | `IOHIDSystem` idle time via `ioreg`, session state correlation | `idle_resume_detected`, `mouse_or_keyboard_activity_after_idle` | monitor cycle | HID idle time parsing failure, idle threshold too short/long | yes | yes | yes |
| Persistence | Launch item enumeration and diffs | `launchagent_added`, `launchdaemon_added`, `login_item_added` | monitor cycle | plist inventory differences, OS version differences | yes | yes | yes |
| Native helper bridge | JSONL ingestion from helper process or socket-backed bridge | canonical physical/session/device/persistence events | event-driven | helper unavailable, malformed JSON, stale offset | yes | yes | yes |

## Expected Event Flow

1. Detector or helper observes a state change.
2. Event is normalized to a canonical event type.
3. Rule registry attaches a rule ID and context.
4. Event is stored in SQLite.
5. Notification policy evaluates the event.
6. Visible alerts are dispatched through the overlay layer.
7. Notification decisions and traces are recorded.

## Known Weak Points

- `pmset` and `ioreg` output formats can change across macOS releases.
- Some lid transitions are reported as `possible_lid_*` until the monitor can confirm state from more than one source.
- Bluetooth address, serial, and product identity can change after sleep or reconnect, so inventory-change events may be noisier than single-device connection events.
- HID idle time is a state transition signal, not a keystroke recorder.

## Recommended Reliability Improvements

- Prefer native helper event sources where available.
- Keep snapshot diff detectors as fallback, not as the only source.
- Normalize all aliases to canonical event types before policy evaluation.
- Keep the alert pipeline separate from detection so one failure does not hide another.
- Preserve evidence context with each alert and alert trace.

