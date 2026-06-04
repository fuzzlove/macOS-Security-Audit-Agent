# CFAA and Hardware Notice Design

## Scope

The root-owned system LaunchDaemon records monitor events locally. A user-session LaunchAgent companion handles visible notices after login. Visible notices are intentionally narrower than event storage so routine informational activity does not train users to ignore warnings.

## Legal Notice

Visible security notices include an authorized-use reminder and state that the indicator is not a legal determination. CVE presence, USB recognition, and local telemetry do not prove unauthorized access or a violation of 18 U.S.C. 1030.

## Login Acknowledgment

The user notification companion opens one authorized-use acknowledgment dialog per GUI login session. The system daemon detector loop continues while the dialog is open. Acceptance is recorded locally with the GUI audit-session identifier and timestamp. Restarting the companion within the same GUI session does not display a second acknowledgment.

## CVE Notices

Vulnerability-review findings are grouped into one digest. The digest is suppressed when its CVE fingerprint is unchanged. High or critical digests use a sound; lower-severity digests remain quiet.

## USB Recognition

The hardware detector snapshots external USB devices through I/O Registry. The initial snapshot establishes a baseline without alerting. A fast observer catches brief disconnect-and-reconnect cycles, waits for a quiet topology window, and then groups newly recognized components into one `usb_device_connected` record and one non-modal Notification Center banner with the `Pop` sound. Repeated enumeration sessions for the same physical component are deduplicated in the visible summary so a single physical reconnect does not produce a burst of notices.

The initial baseline is persisted as a trusted USB inventory. A physical identity not present in that inventory records `new_usb_device_detected` at critical severity, uses the `Pop` sound, and activates the persistent overlay. Reconnecting a previously recorded physical identity remains informational. Serial-numbered devices are tracked independently of transient connection sessions; devices without serial numbers include their port location in the identity.

## Moisture Detection

The hardware detector searches only for explicit moisture, liquid, or water-detection markers exposed through I/O Registry or recent unified logs. It records the capability state in the monitor snapshot. If macOS or the hardware exposes no explicit marker, the status remains unavailable and the agent does not infer moisture from unrelated USB errors.

An explicit new marker records `system_moisture_detected` and sends a critical non-modal notification with the `Basso` sound. If native notification delivery fails, the existing high-priority fallback behavior remains available.

## Persistent Overlay

When enabled, high and critical events update one persistent bottom-right overlay window. The overlay remains visible until acknowledged, does not replace local event storage, and groups repeated events of the same type into a counter. The user notification companion launches the overlay as a separate user-session process so system-daemon detector polling continues while the overlay remains visible.
