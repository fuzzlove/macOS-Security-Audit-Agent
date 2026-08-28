# ClickFix Guard architecture

ClickFix Guard uses a per-user signed background app launched only in an Aqua session. The PySide6 process never installs a global key hook. Observe Mode creates a listen-only Quartz tap; Protect and High Assurance use an active tap and disclose shortcut interception.

The callback matches physical virtual key code 49 with either Command flag, including additional modifiers and repeat key-downs. It checks HID source state and a randomized per-process replay marker, drops every unrelated event, and pushes a four-field immutable record into a fixed 256-entry queue. Overflow and tap disablement are health events. No disk, clipboard, network, XPC, Python, or UI operation occurs in the callback.

The worker performs one bounded pasteboard read, normalizes Unicode, classifies with precompiled bounded patterns, and applies the 64 KiB input, 128 KiB decode, two-layer, 4,096-token, and 100 ms classification limits. It never executes, opens, resolves, imports, or syntax-checks clipboard content. Generic fallback detection remains available if the signed proprietary rule bundle fails, but health becomes degraded; High Assurance must remain fail closed.

In Protect Mode the original chord is suppressed immediately. A safe result is serialized into the native append-only journal and `fsync` completes before a Command + Space key-down/up pair is posted with the private marker. Risky content causes a shortcut record and linked `POTENTIAL_CLICKFIX` incident to be synchronized before warning/containment work; no replay occurs. Classification failure follows profile fail-open/fail-closed policy and is never treated as clean.

The native journal is a crash-recoverable ordered SHA-256 chain. The canonical Python store independently chains shortcut, incident, health, action, and correlation records in atomic SQLite transactions with `synchronous=FULL`, WAL recovery, update/delete denial triggers, checkpoints, and 0600 permissions. Release builds may add signed external checkpoints; the local checkpoint alone is not a substitute for off-device anchoring.

XPC messages are version 1 and capped at 256 KiB. The listener validates the connecting PID’s code signature, Team Identifier, and approved MSAA signing-identifier namespace before exporting records. An explicit developer mode is the only unsigned-development escape hatch and must never be enabled in production.

The 120-second correlation lease consumes NSWorkspace terminal launches and can consume existing MSAA process/network telemetry. Application launch is weak evidence. Endpoint Security `AUTH_EXEC`/`NOTIFY_EXEC` evidence is authoritative only if the approved system extension is installed. No global Terminal deny rule is created.
