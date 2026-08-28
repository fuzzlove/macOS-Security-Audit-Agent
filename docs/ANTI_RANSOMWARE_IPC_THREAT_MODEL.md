# Anti-Ransomware IPC Threat Model

Channels are sensor→engine, engine→containment, engine→notifier, notifier→privileged action broker, and read-only health. Threats include forged local clients, stolen/reused PID, replay, downgrade, oversized/nested messages, path traversal, confused-deputy actions, cross-session disclosure, slow-client pressure, and root compromise.

The protocol validator enforces version, role, boot session, creation age, expiry, connection-bound nonce replay cache, size, depth, enum, finite numbers, UTF-8, strict identifiers, and strict fields. Managed authentication requires an audit-token-derived identity, Team ID, signing ID, designated requirement, and non-ad-hoc signature. Authentication state is invalidated when its connection closes.

Privileged actions are allowlisted by authenticated role. Notifier clients cannot request termination, permanent trust, exact blocks, or engine pause operations. Identity-sensitive actions require incident, event, idempotency key, boot session, PID, PID generation, effective UID, and executable SHA-256 binding. Arbitrary command, signal, and filesystem fields are rejected.

The original native Objective-C authentication boundary accepts an `audit_token_t`, resolves it with `SecCodeCopyGuestWithAttributes` and `kSecGuestAttributeAudit`, validates the designated requirement with `SecCodeCheckValidity`, and compares Team ID, signing identifier, and ad-hoc flags. Its strict syntax compilation passes. A PID or executable path is never used as caller authentication.

The native XPC listener is not built or live-tested, so production authentication remains `NOT_VERIFIED`; mock and source tests cannot close AR-GAP-002.

The privileged API is allowlisted incident acknowledgement and identity-bound containment actions only. It exposes no command string, arbitrary signal, arbitrary PID kill, or filesystem operation.
