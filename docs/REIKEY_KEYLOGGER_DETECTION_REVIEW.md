# ReiKey review and MSAA Keylogger Detection design

## Licensing boundary

ReiKey is GPL-3.0. MSAA reviewed its observable detection architecture but does not copy its Objective-C source. The MSAA scanner is an independent Python implementation using public macOS interfaces and existing command-line tools.

## Adapted ideas

ReiKey demonstrates that an enabled Quartz event tap interested in key-up or key-down events is a strong behavioral capability signal. Useful evidence includes the tap ID, tapping PID and executable, whether the target is system-wide, and whether the tap is passive or can filter events. Signing information and a short persistence/grace check help distinguish durable behavior from temporary system activity.

MSAA adds modern context:

- user and system TCC grants for Input Monitoring (`ListenEvent`) and Accessibility;
- strict code-signature verification, publisher/team metadata where available, and executable provenance;
- higher risk for global taps, active filters, unsigned code, and temporary or broadly writable executable locations;
- durable security events and immediate alert policy for high/critical findings;
- a native helper event alias for newly created keyboard taps;
- explicit coverage warnings when macOS privacy controls prevent complete enumeration.

## Interpretation and privacy

An event tap proves keyboard-event observation capability, not malicious intent. Accessibility and Input Monitoring grants alone are common for password managers, remote-support tools, assistive software, hotkey utilities, and keyboard remappers. MSAA therefore reports permission-only findings as `permission_exposure` at medium severity and raises confidence only when behavioral, scope, trust, path, persistence, or other evidence correlates.

MSAA never creates a keyboard tap, records keystrokes, reads typed content, or stores clipboard content during this scan.

## Native daemon contract

A signed native sensor can use the public Quartz event-tap enumeration API and emit JSON Lines frames when a durable keyboard tap appears. Recommended fields are:

- `event_type`: `keyboard_event_tap_added`
- `source`: `quartz_event_tap_sensor`
- `pid`, `process_name`, path, signing ID, team ID, ancestry, and timestamp
- `evidence`: tap ID, global/target PID, passive-listener/active-filter mode, keyboard event mask, and persistence-after-grace status

The sensor must emit only metadata and must never install a tap or capture key data. Temporary taps should be rechecked after a short bounded grace period. Sensor denial, overflow, and API failure should become health events rather than a clean result.
