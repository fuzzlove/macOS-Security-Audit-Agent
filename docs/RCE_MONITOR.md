# RCE monitor

Memory-corruption, crash-to-execution, executable-memory, and suspected exploitation-chain behavior are documented in [Suspected Remote Code Execution](RCE_SUSPECTED_EXECUTION.md).

## Purpose and architecture

MSAA preserves behavior that could reasonably indicate remote code execution for human review and separately assesses approved local CVE exposure data. The existing root LaunchDaemon is the collection boundary. A deterministic analyzer redacts, correlates, and persists to dedicated tables in the existing SQLite database. CLI review is local and UID-authorized. There is no network listener, payload capture, exploit execution, prevention action, arbitrary shell, or generative model in the decision path.

## macOS coverage

Implemented fallback telemetry is periodic process creation/parent metadata and existing MSAA process, network, file, persistence, service, and package metadata. This mode is visibly `DEGRADED_POLLING`: it can miss short-lived processes and cannot provide complete ancestry, pre-exec authorization, memory transitions, injection, dynamic-library loads, or reliable inbound socket-to-process attribution. Those require a future entitled Endpoint Security adapter. Linux and Windows sensors are unsupported.

Rules cover network-facing service children, inbound-to-exec timing supplied by an approved sensor, service write/execute sequences, writable-path execution, obfuscated interpreter use, inbound/outbound sequences, memory/injection evidence when a future sensor supplies it, crash/restart child anomalies, and remote-administration lookalikes. Detection is monitor-only.

The system daemon also performs bounded, read-only review of recent Apple `.ips` diagnostics under available DiagnosticReports directories. `EXC_BAD_ACCESS`, `SIGSEGV`, `SIGBUS`, stack-protection, heap-corruption, allocator-integrity, and related markers become `RCE-MEMORY-SAFETY-001` review candidates. MSAA stores the report reference, size, SHA-256 hash, process metadata, and normalized crash signals; it does not copy packet payloads or declare that the crash was exploited. Buffer underflow generally lacks a unique crash signature, so it is represented as a memory-safety candidate only when the operating system emitted supporting evidence.

RCE candidates are bridged into the normal MSAA alert pipeline. Sensor-health events remain visibly separate from attack candidates. Critical/high alerts are prioritized over informational backlog, and policy-suppressed items are finalized so they cannot indefinitely starve newer alerts.

Process-injection classification and evidence preservation are documented in [macOS Process Injection](MACOS_PROCESS_INJECTION.md). Unsigned status is supporting context, not proof. Named techniques require their complete deterministic signal set; unmatched multi-signal combinations receive a stable investigation identifier rather than a fabricated name.

## Installation and service lifecycle

The normal MSAA privileged installer owns `com.macos-security-audit-agent.monitor`; RCE is integrated into that daemon. Install the validated config at `/Library/Application Support/MacAuditAgent/config/rce-monitor.json` mode 0600. launchd starts it at boot, restarts failed runs with a 30-second throttle, and sends structured output to `/Library/Logs/MacAuditAgent`. Stop or uninstall with the existing MSAA service installer/uninstaller; evidence is not silently deleted.

Use `msaa rce-monitor status`, `health`, `events-list`, `events-show`, `events-disposition`, `cve-import`, `cve-show`, `config-validate`, and `verify-chain`. Mutating commands require an allowed local UID (root by default). Configuration reload is last-known-good: invalid input generates a health event and is rejected.

`injection-plan <event-id>` displays the classified technique, exact signal basis, unknowns, tools, and evidence checklist. `injection-snapshot` is an explicit authorized action for an existing DFIR case; it collects bounded read-only process, signature, memory-map, open-file/socket, and thread-stack evidence. It never starts packet capture.

## Privacy, response, recovery, and limitations

Command secrets, URL query values, authentication headers, secret-like environment entries, and optionally user paths are redacted before storage. Packet contents are not collected. SQLite uses WAL transactions; first-occurrence event payloads form a tested hash chain, accurately described as tamper-evident rather than tamper-proof. Back up the database while the daemon is stopped or through SQLite-aware tooling, restore it with owner-only permissions, then run `verify-chain`.

An alert is evidence for review, not proof of compromise or a CVE. Preserve the host timeline and follow approved response procedures. The daemon cannot detect every RCE and must never report sensor silence as safety.

CVE association is limited to administrator-approved local records and deterministic product/version or explicitly qualified behavioral comparisons. A crash alone cannot establish a zero-day, an n-day, remote origin, attacker control, or successful code execution. Lockdown Mode reduces some attack surface but is not used as evidence that compromise is impossible.
