# Anti-Ransomware Containment Model

## Implemented coordinator

`ContainmentCoordinator` persists every transition before returning it and accepts actions only through an injected native boundary. Pause ordering is `VALIDATING → EVIDENCE_PRESERVED → PAUSE_REQUESTED → PAUSED`. Exact revalidation compares PID, PID version, effective UID, boot session, executable path and hash, script identity, audit-token hash, executable file identity, CDHash, and process start time.

Lease rows persist the complete expected process identity, policy, owner, expiry, renewal limits, no-user policy, criticality, evidence state, and rollback action. Each transition also creates an append-only containment action and hash-chain custody entry.

Restart reconciliation never signals a changed identity. Expired paused leases transition through `LEASE_EXPIRED → ROLLBACK_REQUESTED → ROLLED_BACK` when the configured rollback is verified. Missing processes become `PROCESS_EXITED`; identity changes become a recorded failure requiring review.

The native self-test fixture accepts no PID or path input. It creates its own temporary marked root and child, verifies SIGSTOP, SIGCONT, bounded rollback, SIGTERM, cleanup, and zero remaining suspended fixtures. This is safe local fixture evidence, not a production privileged-helper qualification.

The native containment boundary now independently captures and revalidates effective UID, start seconds/microseconds, executable path, device/inode, and a streaming executable SHA-256. It accepts only the pause, resume, and terminate action enum; refuses PID 1, itself, launchd, login infrastructure, MSAA, and VoiceOver identities; and uses bounded polling to verify `SSTOP`, resumed state, or `SZOMB` after signaling.

The native watchdog owns a fixed 256-lease array, monotonic expirations, one-shot rollback, and explicit rollback/failure counters. It contains no Python or Qt dependency. Durable restart loading and authenticated XPC integration remain required before production use.

The persisted lease state machine covers request, validation, identity/policy/critical rejection, evidence preservation, pause, pending decision, resume, termination, expiry, rollback, process exit, failure, and closure. Exact identity includes boot session, PID generation, executable hash, script hash, and user context. Evidence is mandatory before action. A native watchdog must own live leases; Python state-machine tests do not establish live containment.
