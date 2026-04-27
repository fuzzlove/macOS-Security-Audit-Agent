# Background Monitor UAT

## Preconditions

- Run the desktop app as the logged-in macOS user.
- Do not use `sudo` for the user LaunchAgent workflow.
- Expected plist path:
  `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist`
- Expected launchctl domain:
  `gui/<uid>`

## Test Cases

### 1. Install LaunchAgent

Action:
- Open `Background Monitor`.
- Click `Install Background Monitor`.

Expected:
- `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist` exists.
- `launchctl print gui/<uid>/com.mac-audit-agent.monitor` works.
- Monitor health shows `LaunchAgent installed: yes`.

### 2. Start monitor

Action:
- Click `Start Monitor`.

Expected:
- No `sudo` prompt is required.
- Monitor health shows `LaunchAgent loaded: yes`.
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

### 10. Permission denied / notification denied

Action:
- Simulate a notification or database write failure.

Expected:
- UI shows a clear warning.
- `~/Library/Logs/MacAuditAgent/monitor.log` contains the fallback error entry.
- The app does not crash.
