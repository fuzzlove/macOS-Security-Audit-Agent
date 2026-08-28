# Process Injection Monitor

MSAA identifies and preserves known, partial, variant, and previously unmodeled process-manipulation behavior for authorized human review. It runs inside the existing macOS system LaunchDaemon and RCE analyzer. It does not inject code, modify processes, execute payloads, suppress candidates automatically, or claim complete visibility.

The pipeline is: structured sensor event → normalized primitive → stable process identity → evidence-backed behavior graph → temporal template comparison → variant/novelty/context analysis → immutable RCE observation → separate review/research/evidence records. Process identity includes host, boot, PID, start time, executable hash, audit token, and workload/container identity where supplied, preventing PID-only correlation.

macOS polling provides degraded process metadata. Existing `vmmap`, signing, dylib, file, network, persistence, and evidence components provide bounded enrichment. Reliable task-port, cross-task memory, and thread-state provenance requires a future signed and entitled native sensor. Linux and Windows primitive-provider interfaces are modeled but their sensors are not implemented.

The monitor distinguishes no candidates from no telemetry, partial coverage, degraded coverage, analysis failure, and evidence failure. Installation, upgrade, and recovery use the existing MSAA LaunchDaemon installer. After upgrade validate schema, rules, sensor health, ATT&CK status, and the RCE evidence chain.
