# ClickFix Guard testing

Run headless tests without initializing PySide6:

```bash
python3.12 -m mac_audit_agent.clickfix doctor
python3.12 -m mac_audit_agent.clickfix status --json
python3.12 -m mac_audit_agent.clickfix test-alert
python3.12 -m mac_audit_agent.clickfix test-classifier --fixture safe
python3.12 -m mac_audit_agent.clickfix test-classifier --fixture clickfix
python3.12 -m mac_audit_agent.clickfix verify-evidence
python3 -m pytest -q tests/test_clickfix_guard.py
```

Native unit tests are under `native/ClickFixGuard/Tests` and run with `swift test` on a full Xcode installation. Fixtures are inert, use `.invalid` destinations, and are classified as strings only. They never invoke a shell, interpreter, URL loader, or system-setting change.

Release UAT must use separately authorized disposable macOS hosts and test built-in/external keyboards, left/right/both Command keys, additional modifiers, repeat, rapid events, alternate layouts, replay recursion, queue overflow, tap timeout/re-enable, locked session, fast user switching, displays, Secure Keyboard Entry, pasteboard lazy providers/denial/timeouts, 64 KiB boundaries, image/file-only content, notification permission/Focus, GUI restart restoration, and launchd crash recovery.

Protection UAT must instrument ordering to prove durable journal synchronization precedes replay; risky and fail-closed cases must produce no replay. Verify quarantine only when visibly enabled and that it never restores automatically. Verify unauthorized XPC clients are rejected using a differently signed fixture.

Correlation UAT must separate audit sessions and cover no follow-on activity, each supported terminal, interpreter/download/security/persistence execution, outbound connections, lease expiry, unrelated sessions, sequence gaps, and Endpoint Security unavailable/available states. Only an actual ES authorization response may be labeled blocked.

Universal validation commands:

```bash
cd native/ClickFixGuard
MSAA_CODESIGN_IDENTITY='Developer ID Application: …' MSAA_TEAM_IDENTIFIER='…' ./build.sh
lipo -archs .build/universal/MSAAClickFixGuardAgent.app/Contents/MacOS/MSAAClickFixGuardAgent
codesign --verify --strict --deep --verbose=2 .build/universal/MSAAClickFixGuardAgent.app
```
