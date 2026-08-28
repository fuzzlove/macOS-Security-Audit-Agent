# AR-GAP-003 Threat Model

Protected assets are process-signal authority, sensor-originated target identities, prepared tokens, active leases and incident evidence. Adversaries include an unprivileged local process, compromised notifier, unsigned source Python, replaying client, PID-reuse attacker, binary replacement attacker and a privileged attacker able to kill local services.

Controls include audit-token-derived caller code validation, exact Team/signing/designated requirements, connection-bound replay cache, strict bounded messages, incident/event-only engine requests, sensor-only identity registration, short monotonic expiry, PID version and boot binding, live start/file/hash/signing checks, critical identity policy, two-phase durable prepare, watchdog-before-pause ordering, post-signal verification and append-only transitions.

Residual risks: POSIX signaling is PID addressed; controls minimize but cannot eliminate the final race. A root-capable attacker can alter local services or evidence. Helper-SIGKILL survival requires the separately signed guardian and live qualification. No claim of tamper-proof behavior or complete ransomware prevention is made.
