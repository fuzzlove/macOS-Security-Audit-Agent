# Anti-Ransomware Containment Safety

Automatic containment is refused for any process marked critical, including accessibility and continuity services. Evidence must already be preserved. Every action revalidates the complete expected identity; PID reuse, path replacement, hash replacement, boot changes, audit-token changes, and start-time changes are rejection conditions.

The production API remains unavailable until authenticated native IPC and a signed privileged helper are live-qualified. The Python coordinator cannot send OS signals by itself. The native test fixture is deliberately self-contained and exposes only `--self-test`; it cannot accept an arbitrary PID, path, command, or signal.

Native action verification is bounded to approximately 200 ms and checks stopped, resumed, or zombie state. The helper core revalidates after pause/resume. The pidversion originates in the authenticated Endpoint Security identity; start time, UID, file identity, path, and SHA-256 provide independent current-process checks. Production integration must additionally compare the current audit-token generation at the native IPC/Endpoint Security boundary.

No generic kill or command API exists. PID reuse and identity changes reject action. Critical OS, identity, encryption, backup, emergency, accessibility, and MSAA services are monitored but require narrow approved handling. Lease expiry transitions to rollback. Current pause/resume/terminate operations are not live-tested and remain unavailable.
