# Codex GUI Test Policy

Codex and unattended automation are headless by default. They must not instantiate the Cocoa Qt platform plugin merely because PySide6 imports successfully.

Set both:

```bash
MSAA_GUI_AUTOMATION_MODE=1
MSAA_GUI_TEST_BACKEND=offscreen
```

before widget logic or rendering tests. `minimal` is permitted only for compatible tests. Both modes disable native tray and notification assumptions. `interactive-aqua` requires a confirmed graphical session and a dedicated human-driven harness; it is never authorized by the environment variable alone when root, LaunchDaemon, unsupported Python, or no Aqua session is detected.

Headless tests should exercise event creation, persistence, policy, acknowledgment, and delivery state without importing Qt. Cocoa lifecycle probing occurs only in `python3.12 -m mac_audit_agent.runtime.qt_probe`, after static preflight, in a short-lived subprocess with timeout and signal reporting.
