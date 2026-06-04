# Objective-See Alert Review

This review uses Objective-See projects as architectural reference only. No Objective-See code was copied.

## ProcessMonitor

- Relevant pattern: Endpoint Security based process events with structured JSON-like output, including process path, PID, parentage, arguments, architecture, and signing context.
- How it informs our fix: real detector output should become canonical structured events before policy. Process execution evidence should carry enough context for an analyst to decide whether it is expected.
- License note: upstream source licensing must be reviewed before any code reuse. This project uses the pattern only.
- Implementation recommendation: keep `unexpected_process_execution`, shell-spawn, temp-binary, and low-trust execution events in the mandatory visible alert registry.

## FileMonitor

- Relevant pattern: Endpoint Security based file events with process attribution and JSON-like records.
- How it informs our fix: file and persistence evidence should include the acting process and path before alerting, rather than emitting generic strings.
- License note: design inspiration only unless licensing is explicitly handled.
- Implementation recommendation: persistence and tamper detectors should store canonical event type, original event type, path, process context, and evidence hash before notification policy.

## BlockBlock

- Relevant pattern: continual persistence monitoring with user-facing alerts when persistent components are added or changed.
- How it informs our fix: persistence, admin, and monitor-tamper events are never log-only by default. They must visibly alert and preserve evidence for review.
- License note: BlockBlock is GPL-3.0; do not copy code into this project without resolving license compatibility.
- Implementation recommendation: keep detector collection separate from alert rendering, but make persistence events mandatory visible alerts.

## KnockKnock

- Relevant pattern: persistence enumeration, baseline-style review, and analyst-oriented classification rather than overclaiming compromise.
- How it informs our fix: visible alerts should say what changed and what to verify, without claiming compromise unless evidence is direct.
- License note: design reference only.
- Implementation recommendation: keep persistence enumeration as a fallback and correlate it with event-driven alerts where available.

## TaskExplorer

- Relevant pattern: process context, trust/signing information, loaded resources, open files, and network context.
- How it informs our fix: possible compromise alerts should be evidence-rich and show process, path, network endpoint, signature, and parent context when available.
- License note: design reference only.
- Implementation recommendation: enrich `EventAlertTrace` and alert details instead of using terse detector messages.

## ReiKey

- Relevant pattern: keyboard event tap awareness and monitoring for persistent key interception mechanisms.
- How it informs our fix: keyboard/input-related security signals need a visible user-session alert path that does not depend on Notification Center.
- License note: design reference only.
- Implementation recommendation: map keyboard, mouse, trackpad, and HID aliases into canonical input-after-idle events and route them to the Authorized Use Notice overlay.

## OverSight

- Relevant pattern: user-facing camera and microphone awareness.
- How it informs our fix: privacy-sensitive activity should be visible and understandable, not buried in logs.
- License note: design reference only.
- Implementation recommendation: use the same visible alert pipeline for privacy/session signals and record delivery status.

## Implementation Recommendations Applied

- Normalize detector aliases before policy and storage.
- Store `original_event_type` and canonical `normalized_event_type` in the alert trace.
- Make the mandatory visible alert registry authoritative for default alert policy.
- Use one final visible renderer, `show_visible_security_alert(...)`, for demo, real, notifier, and Authorized Use Notice alerts.
- Start visible-alert cooldown only after successful overlay dispatch.
- Keep notifier cursor, queue, policy, suppression, overlay result, and DB path visible in diagnostics.

## Sources Reviewed

- https://github.com/objective-see/BlockBlock
- https://objective-see.org/products/utilities.html
- https://github.com/objective-see/ProcessMonitor
- https://github.com/objective-see/FileMonitor
- https://github.com/objective-see/TaskExplorer
- https://github.com/objective-see/ReiKey
- https://github.com/objective-see/OverSight
