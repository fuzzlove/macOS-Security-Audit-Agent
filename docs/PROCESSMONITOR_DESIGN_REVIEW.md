# ProcessMonitor review and MSAA process-explorer adaptation

## Scope and licensing

Objective-See ProcessMonitor is GPL-3.0. MSAA uses it as an architectural reference and does not copy its Endpoint Security or Objective-C implementation.

## Findings

ProcessMonitor subscribes to Endpoint Security exec, fork, and exit notifications. Its process records include PID, parent and responsible PID, effective user, executable path, arguments, optional environment, ancestry, architecture, exit status, audit identity, code-signing flags, signing/team IDs, platform-binary status, and code-directory hash.

This event-driven model closes important gaps in periodic `ps` polling: short-lived processes are retained, exit status is available, fork and exec are distinct, and PID reuse can be separated using process start identity. Endpoint Security requires root, user approval, and Apple’s restricted client entitlement, so it cannot be treated as an unconditional Python dependency.

## Implemented adaptation

MSAA now has a reusable process-explorer backend with:

- a no-dependency `ps` snapshot fallback including PID, PPID, UID/user, state, CPU, memory, start time, path, and a PID/start/path identity;
- normalized native `exec`, `fork`, and `exit` ingestion;
- responsible PID, ancestry, architecture, signing ID, team ID, platform-binary state, code-signing flags, CDHash, and exit status;
- explicit PID-reuse detection and bounded exited-process history;
- bounded arguments and ancestry;
- environment collection disabled by default at the sensor boundary, with sensitive values redacted and record counts/value lengths bounded if a native sensor supplies it.

The keylogger scanner now uses this shared process snapshot backend for event-tap PID attribution. Native security-event frames also preserve the expanded process identity fields.

## Native sensor recommendations

A future signed helper should use Apple’s Endpoint Security framework and emit structured JSONL records rather than linking GPL code. It should report capability failures (`not entitled`, `not permitted`, `not privileged`) as health states, subscribe only to required notification events, handle message-version differences, monitor queue pressure/dropped events, and disable environment collection unless a narrowly justified diagnostic mode explicitly enables it.

The task-explorer UI should remain read-only by default. Termination, suspension, or file-removal actions require a separate confirmation and evidence-preservation workflow; process presence or an unsigned signature alone is not proof of malware.
