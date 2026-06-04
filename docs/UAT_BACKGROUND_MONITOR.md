# Background Monitor UAT

## Preconditions

- Install the detector with administrator approval.
- Expected detector plist path:
  `/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist`
- Expected logged-in user notification companion plist path:
  `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist`
- Expected launchctl domain:
  `gui/<uid>`

The detector must run as a system daemon. The user LaunchAgent is a notification companion only and must not run the detector loop.

## Test Cases

### 1. Install system daemon and user notifier

Action:
- Open `Background Monitor`.
- Click `Install System Monitor + User Notifier` with administrator approval.

Expected:
- `/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist` exists.
- `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist` exists.
- `launchctl print system/com.mac-audit-agent.monitor` works after start.
- `launchctl print gui/<uid>/com.mac-audit-agent.monitor` works.
- Monitor health shows the system launchctl domain.

### 2. Start monitor

Action:
- Click `Start Monitor`.

Expected:
- Administrator approval is required for the system daemon.
- Monitor health shows the system daemon as loaded.
- Monitor PID is visible.
- Heartbeat updates within 60 seconds.

### 3. Generate test event

Action:
- Click `Generate Test Event`.

Expected:
- Event appears in the recent events table.
- Event is saved in SQLite immediately.
- A user notification appears.
- Event appears in exported JSON and HTML when monitor logs are included.

### 4. Display sleep/wake

Action:
- Lock the screen or sleep and wake the display.

Expected:
- A screen or system wake/sleep or lock/unlock event is logged when detectable.
- A user notification appears.

### 5. Camera/process simulation

Action:
- Open FaceTime, Photo Booth, Zoom, Teams, or QuickTime Player.

Expected:
- `camera_activity_suspected` or `capture_process_observed` is logged.
- A notification appears.
- Confidence remains `low` or `medium` unless a public API confirms active use.

### 6. Screen sharing posture

Action:
- Enable or disable Screen Sharing in System Settings.

Expected:
- `screen_sharing_enabled` or `screen_sharing_disabled` is logged.
- A notification appears.

### 7. Stop monitor

Action:
- Click `Stop Monitor`.

Expected:
- Monitor process stops.
- Heartbeat stops advancing.
- UI shows `stopped`.

### 8. Restart after logout/login

Action:
- Log out and back in.

Expected:
- LaunchAgent starts automatically.
- A new heartbeat appears.

### 9. Export logs

Action:
- Export JSON or HTML with background monitor logs included.

Expected:
- Monitor events are present in the export.
- Camera video, microphone audio, screen contents, keystrokes, and packet contents are not included.

### 10. USB reconnect recognition

Action:
- Unplug and reconnect a previously trusted USB device.

Expected:
- One grouped `usb_device_connected` event is recorded after the quiet window.
- The Notification Center banner uses the `Pop` sound.
- The event remains informational and does not activate the persistent overlay.

### 11. First-seen USB device

Action:
- Connect a USB device that has not been seen before by the current trusted inventory.

Expected:
- `new_usb_device_detected` is recorded at critical severity.
- The `Pop` sound is used.
- The persistent bottom-right overlay becomes active until acknowledged.

### 11a. Connected Bluetooth device

- Connect an approved Bluetooth keyboard, mouse, trackpad, or accessory.
- Confirm `bluetooth_device_connected` is logged with `hardware_detector` and `ioreg_bluetooth` provenance.
- Confirm the translucent bottom-right overlay appears.
- Confirm the monitor does not actively scan for ambient nearby devices.
- The event is saved locally and appears in exports.

### 12. New network IP assignment

Action:
- Join a new Wi-Fi or Ethernet network so the active interface receives a new IP assignment.

Expected:
- `network_ip_assigned` is recorded at informational severity.
- A subtle grey bottom-right overlay appears.
- The event remains logged locally and appears in exports.

### 13. New VPN connection

Action:
- Connect a VPN profile that creates a new tunnel interface.

Expected:
- `vpn_connected` is recorded at informational severity.
- A subtle grey bottom-right overlay appears.
- The event remains logged locally and appears in exports.

### 14. Permission denied / notification denied

Action:
- Simulate a notification or database write failure.

Expected:
- UI shows a clear warning.
- `~/Library/Logs/MacAuditAgent/monitor.log` contains the fallback error entry.
- The app does not crash.

### 15. New startup daemon or persistence item

Action:
- Add a new LaunchDaemon, LaunchAgent, or login item on a test machine.

Expected:
- New `/Library/LaunchDaemons` entries trigger a critical `launchdaemon_added` alert.
- New LaunchAgents or login items trigger a critical persistence alert.
- The monitor log records the previous and current persistence inventories.
- The event is saved locally and appears in exports.

### 16. System daemon install

Action:
- Install the monitor with `MAC_AUDIT_AGENT_LAUNCH_SCOPE=system`.

Expected:
- The plist is written to `/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist`.
- The runtime root is shared under `/Library/Application Support/MacAuditAgent/runtime`.
- Logs are written under `/Library/Logs/MacAuditAgent`.
- The daemon reports `system` as its launchctl domain.

### 17. Input resumes after idle

Action:
- Leave the keyboard, mouse, and trackpad untouched for 2 minutes, then resume input.

Expected:
- `input_activity_resumed_after_idle` is recorded at medium severity.
- `input_activity_idle_started` is recorded when aggregate HID input remains idle past the configured threshold.
- Confirm that neither event stores keystrokes, pointer coordinates, nor screen content.
- The authorized-use CFAA reminder dialog appears again after the idle period.
- The event is stored locally and appears in the recent events table.

### 18. Show Context timeline

Action:
- Select a finding in Results and click `Show Context`, or select a monitor event and click `Show Context`.

Expected:
- A timeline opens showing activity 15 minutes before and 15 minutes after the selected item.
- The context view includes scan summaries, monitor events, persistence changes, network changes, USB changes, session events, and admin-related changes that fall inside the window.
- The dialog shows evidence only and does not infer compromise.
