# ClickFix Guard privacy model

ClickFix Guard is an exact-interaction sensor, not a keylogger. The event tap may retain only event type, Space virtual key code, modifier flags, source-state metadata, replay marker comparison, and monotonic time for a matching physical Command + Space event. It does not retain characters, search text, passwords, Terminal input, unrelated timing, secure-field data, or full key sequences.

Clipboard content is extracted only after that match, during the inert self-test, or during an authorized reassessment. Change count may be observed without content. Text inspection is bounded; images, files, and unsupported binary types are recorded without arbitrary decoding. No URL is opened and no content is executed.

Ordinary evidence contains SHA-256, change count, content type, sizes, line count where available, static classification, risk categories, entropy/encoding indicators where available, a short secret-redacted preview, timestamp, classifier identity, confidence, and truncation. Full raw commands are excluded from standard journals, database records, diagnostics, tooltips, notifications, and lock-screen content.

The foreground application at detection or clipboard-change time is context only. Records use `UNKNOWN`, `FOREGROUND_APP_AT_CHANGE`, and `LOW`; MSAA never claims that application wrote the clipboard. Quartz HID source state is also evidence, not proof against a privileged synthesizer.

When quarantine policy is explicitly enabled, the native agent preserves the bounded original text with AES-GCM under a random per-device key held in the user Keychain (`AfterFirstUnlockThisDeviceOnly`). Vault files are mode 0600. Restoration is available only through the same-Team XPC action with a justification and produces a chained audit record; it never marks content safe or restores automatically. Deployments must still define retention/export policy and may disable recoverable preservation where policy forbids it.
