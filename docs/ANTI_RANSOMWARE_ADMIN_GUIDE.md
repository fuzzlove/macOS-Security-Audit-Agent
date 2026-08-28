# Anti-Ransomware Administrator Guide

`DEGRADED` or `OBSERVE` is not preemptive protection. Review `msaa anti-ransomware doctor --json`, AR022, sensor signature/entitlement, system-extension approval, FDA, heartbeat, live-event, sequence-gap, helper IPC, policy/rule signature, and self-integrity fields.

Safe validation uses only a newly created temporary directory, at most 20 files of at most 1 MiB, no process signals, no PF rules, and no user documents. Canary deployment is opt-in and creates harmless randomized content only in an explicitly selected directory.

Do not terminate a process by name or path. Production containment requires a sensor-originated process identity, PID version/start time/CDHash/file identity revalidation, preserved evidence, bounded authorization, protected critical-process policy, and action verification.
