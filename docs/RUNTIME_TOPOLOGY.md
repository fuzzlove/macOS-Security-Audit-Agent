# MSAA Runtime Topology and Service Threat Model

`mac_audit_agent.runtime.topology.resolve_runtime_topology()` is the canonical source for monitor mode, databases, executable arguments, launchd domains, logs, ownership, and source/frozen identity. Settings storage is never used as an implicit substitute for the event database.

## System monitor mode

- Monitor: system LaunchDaemon `com.mac-audit-agent.monitor` in the `system` launchctl domain.
- Event evidence: `/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3`, written by the root monitor.
- User notifier: LaunchAgent `com.mac-audit-agent.user-notifier` in `gui/<uid>`.
- Notifier transport: read-only SQLite access to the canonical system event database.
- Receipt and render traces: `~/Library/Application Support/MacAuditAgent/alert_receipts.sqlite3`, a distinct per-user receipt database writable only by that user. It is not the settings database and is not protected monitor evidence.
- Source launch: `sys.executable -m mac_audit_agent.monitor` and `sys.executable -m mac_audit_agent.user_notifier`.
- Frozen launch: the installed MSAA executable with an internal service flag. No Python command, Homebrew path, checkout path, or `PYTHONPATH` is used.

The notifier cannot update or delete protected event evidence. It copies the minimum event fields needed for policy/display into its private receipt store, records cursor movement and rendering there, and opens the system database using SQLite `mode=ro`. The database, WAL, and SHM must share the same restricted read group and must never be world-readable or user-writable. Deployment must verify access as the intended console identity. The system monitor remains the sole evidence writer. A compromised user notifier can disclose events already readable by that user or falsify its own display receipts, but cannot rewrite protected evidence. A dedicated notifier group is preferred; membership is limited to intended console users.

## User monitor mode

The monitor and notifier use the user's database and `gui/<uid>` domain. A system daemon must not simultaneously run. Switching to system mode reports a surviving user monitor as `MON005` until it is explicitly removed.

## Stable health codes

- `MON001` daemon not installed; `MON002` not loaded; `MON003` not running; `MON004` stale heartbeat; `MON005` conflicting deployment.
- `ALT001` notifier source mismatch; `ALT002` notifier heartbeat stale; `ALT003` diagnostic event not received.

## Pre-UAT status semantics

`PASS` is fully verified. `DEGRADED` preserves correct core operation with an unavailable optional feature. `WARN` is a verified non-blocking risk. `SKIPPED` is intentionally not applicable. `NOT_VERIFIED` is applicable work that could not run. `FAIL` is required behavior that failed. `BLOCKER` is a critical required failure. `HARNESS_ERROR` means the audit mechanism failed. A blocker, failure, harness error, or required not-verified result prevents UAT readiness; contradictory nested evidence is normalized to failure before report counting.
