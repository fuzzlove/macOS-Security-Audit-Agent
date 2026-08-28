# OverSight design review and MSAA adaptation

## Scope and licensing boundary

OverSight was reviewed as a behavioral and architectural reference for camera and microphone monitoring. It is GPL-3.0 software. MSAA does not copy its Objective-C implementation; the changes here are an independent Python/native-event contract derived from observable security-monitoring patterns.

## Useful patterns found

OverSight treats capture monitoring as two related signals:

1. Camera or microphone device state establishes that capture began or ended.
2. Process attribution may arrive shortly afterward and identifies a likely client.

It also watches capture-device connection and removal, preserves start/stop lifecycle state, suppresses repeated device notifications, and presents a concise alert containing the device and client identity. Those patterns are substantially stronger than inferring capture merely because Zoom, a browser, or another capture-capable application is running.

## Patterns intentionally not adopted

- OverSight uses private or version-sensitive Apple logging interfaces for some attribution paths. MSAA accepts structured events from a separately signed native sensor instead, with stable aliases and graceful unattributed events.
- MSAA does not terminate a process from an alert. An unexpected event is evidence for review, not sufficient proof that killing a process is safe.
- MSAA does not ignore every device whose name contains `Virtual`. Virtual cameras and microphones are retained and can be higher-interest device lifecycle events.
- MSAA never captures camera images, microphone audio, screen contents, or keystrokes.

## Implemented MSAA improvements

The native event bridge now accepts camera and microphone start/stop aliases, confirmed microphone activity, and capture-device connection/removal. Every device transition becomes a durable security event even when process attribution is unavailable. When attribution is present, bounded process arguments, ancestry, signing ID, team ID, and platform-binary status are retained in metadata.

Capture starts default to high severity. A start while the screen/session is locked or after idle is elevated to critical and marked as suspicious context. External, virtual, or first-seen capture devices are high priority. Stops remain durable timeline events but do not notify by default.

Recommended native-helper payloads are JSON Lines records containing:

- `event_type`: `camera_on`, `camera_off`, `microphone_on`, `microphone_off`, `av_device_connected`, or `av_device_disconnected`
- `source`: the documented listener that observed the transition
- `timestamp`, `pid`, `process_name`, and signing fields when known
- `evidence`: `device_id`, `device_name`, `media_type`, `external`, `virtual`, `first_seen`, `screen_locked`, `session_locked`, and `after_idle` as available

The helper should use documented AVFoundation device discovery/notifications plus documented CoreAudio or CMIO state listeners appropriate to its deployment target. Attribution may be emitted with the state event or as enriched evidence, but missing attribution must never discard the device-state event.

## Further native work

The remaining platform-specific improvement is a signed, hardened native sensor that emits the structured contract above. It should keep a short attribution grace window, report dropped/overflowed signals as monitor-health events, deduplicate identical state transitions per stable device ID, and expose capability status so the UI can distinguish unsupported APIs from an inactive camera or microphone.
