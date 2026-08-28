# Alert Preview / Force Rendering Audit

Generated: 2026-07-08

## Summary

MSAA had unsafe preview and interactive test paths that could call
`NotificationManager.show_visible_security_alert()` from a UI helper, Pre-UAT
process, CLI process, or Codex/Terminal process. That path can launch
`security_overlay.py`, which initializes Qt/AppKit outside the running user
notifier GUI domain.

The corrected model is:

Caller -> `BackgroundMonitorEvent` -> active DB queue -> notifier wake marker /
kickstart -> `com.mac-audit-agent.user-notifier` -> `AlertOverlayManager` ->
overlay state/window confirmation -> `EventAlertTrace`.

## Entry Points

| Path | Function | Context | Previous Behavior | Required Behavior | Status |
| --- | --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/background_monitor_panel.py` | `test_bottom_right_alert()` | Main UI | Wrote events and directly called `show_visible_security_alert(..., force=True)` | Queue preview events with force metadata and wake notifier | Fixed |
| `mac_audit_agent/ui/background_monitor_panel.py` | `preview_alert_styles()` | Main UI | Delegated to direct preview path | Delegates to notifier-queued preview path | Fixed |
| `mac_audit_agent/ui/background_monitor_panel.py` | `test_critical_alert()` | Main UI | Used simulated event path that could notify directly | Builds diagnostic critical event, queues it, wakes notifier | Fixed |
| `mac_audit_agent/quality/alert_auditor.py` | `_run_visible_alert_probe()` | Pre-UAT | Simulated event and directly rendered from audit process | Queues event, waits for notifier trace confirmation | Fixed |
| `mac_audit_agent/notification_manager.py` | `_ensure_security_overlay_process()` | Renderer | Could launch overlay from any process with a `NotificationManager` | Blocks non-notifier/non-main-GUI contexts and Python 3.14 GUI runtime | Fixed |
| `mac_audit_agent/alerts/test_realtime_alerts.py` | CLI harness | CLI | Not present | Queues preview/force/category events and optionally waits for notifier confirmation | Added |

## Unsafe QApplication / AppKit Creation Paths

The direct `QApplication(...)` creation sites remain limited to the main app,
tests, and `security_overlay.py`. The new `gui_context` guard prevents normal
CLI, Pre-UAT, daemon, Codex, and Terminal paths from launching the overlay.

## Trace Semantics

`visible_alert_id` is now written only after overlay launch confirmation.
Preview/force events queued for the notifier start with
`render_verification_status=queued_not_yet_rendered`; interactive checks pass
only after the notifier records `verified_by_notifier_window_state` or a visible
alert ID.

## Remaining Operational Step

After source changes are deployed to the runtime package, run:

```bash
python3 -m mac_audit_agent.user_notifier_doctor --repair
python3 -m mac_audit_agent.alerts.test_realtime_alerts --force --severity critical --interactive
```

The first command refreshes the LaunchAgent runtime copy. The second verifies
that the running notifier consumes the event and confirms overlay visibility.
