# ClickFix Guard source review

## Scope and findings

The repository review covered the existing bottom-right alert stack, durable alert controller, SQLite stores, integrity chain, notification manager and notifier process, process/network correlation, LaunchAgent installers, native anti-ransomware sensor, peer-authentication code, Endpoint Security readiness documents, signing scripts, PyInstaller packaging, operational-health panel, and GUI preflight.

Reusable components include the `AlertStack` card surface, `EvidenceStore` hash-chain design, MSAA severity vocabulary, tray integration, `UserNotifications` delivery patterns, launchd installation conventions, code-signing verification, and existing process/network telemetry. ClickFix uses a separate schema because a suppressed shortcut must be synchronized before replay and because clipboard evidence has a distinct privacy boundary.

Defects or gaps found before this work:

- The existing `AlertStack` was not wired into a persistent feature controller and keyed cards only by event ID, which could collide when one event creates multiple alerts.
- The generic durable alert controller was specialized for security-control events and could not atomically link a ClickFix shortcut and incident.
- There was no signed graphical-session native exact-shortcut sensor, authenticated ClickFix XPC surface, ClickFix clipboard policy, or ClickFix CLI.
- Existing Endpoint Security documentation correctly treats authorization containment as externally gated; no entitled ClickFix execution containment implementation was present.
- Existing notification delivery cannot prove user visibility, especially under Focus or revoked permission.

## New components and reuse

`native/ClickFixGuard` is a Swift Package producing the `com.macos-security-audit-agent.clickfix-guard` background app. It owns the Quartz event tap, pasteboard reads, static classifier, replay marker, quarantine operation, native notification request, application-launch correlation, signed rule-bundle verification, native journal, and signing-identity-gated XPC service. Python owns canonical event/incident persistence, durable alert presentation, Alert Center, health UI, CLI, and ingestion of the verified native journal.

The native classifier bundle logs only bundle identity/version. Complete detection expressions and scoring weights are not presented in the UI, tooltips, ordinary logs, or reports. The included bundle is signed by a development trust root; production release engineering must replace it with the production public root and an offline-produced signature.

## Data flow

```text
HID Command + Space
  -> Quartz callback (key code/flags/source state/time only)
  -> fixed 256-record queue
  -> worker: NSPasteboard bounded read -> signed static classifier
  -> fsync native hash-chain journal
       -> risky: fsync linked incident; no replay; optional quarantine
       -> safe: tagged synthetic Command + Space replay in Protect Mode
  -> same-Team authenticated NSXPC fetch / verified journal consumer
  -> canonical SQLite hash chain + durable alerts
  -> bottom-right stack, Alert Center, tray badge, native notification
  -> 120-second NSWorkspace/process/network/ES correlation boundary
```

## Privacy boundary

The callback has no AppKit, pasteboard, file, network, Python, or UI calls. Nonmatching events are immediately returned and never enqueued. Standard journals store hashes, lengths, categories, confidence, redacted preview, and attribution confidence—not complete clipboard text. Clipboard content is read only on a matching shortcut or explicit self-test/reassessment. Foreground-at-change context is an inference and is never recorded as authoritative clipboard authorship.

## Permissions and signing

Observe Mode requires operational Input Monitoring. Protect Mode additionally needs Accessibility for reliable replay. Pasteboard access behavior is macOS-version and privacy-policy dependent. Notifications require user authorization. The agent and MSAA application must share the approved Team Identifier, use hardened runtime, retain the stable bundle identifiers, and be notarized together. See `clickfix_guard_permissions.md`.

## Tests added

Python tests cover safe/risky/unavailable classification, atomic linkage, replay rejection, immutable records, tamper detection, raw-content exclusion, CLI headless boundaries, and callback privacy. Swift tests cover chord matching, additional modifiers, replay/non-HID rejection, bounded queue overflow, inert classifier fixtures, and journal integrity. Physical HID, TCC, Focus, notification routing, fast-user-switching, secure-input, and signed universal builds require the macOS UAT matrix described in `clickfix_guard_testing.md`.

## Platform limitations

Quartz source-state metadata is the best supported distinction between HID and generated events, but a sufficiently privileged local process may synthesize misleading events. Secure Keyboard Entry and lock/login-window sessions can prevent delivery. Pasteboard APIs do not authoritatively identify the writer. NSWorkspace launch evidence does not prove command execution. Endpoint Security correlation is authoritative only when the separately approved, entitled sensor reports the execution; this implementation reports that capability as unavailable otherwise. Apple signing, notarization, TCC grants, Intel hardware execution, and Endpoint Security entitlement cannot be manufactured or certified by repository code.
