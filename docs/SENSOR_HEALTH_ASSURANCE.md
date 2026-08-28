# Sensor Health Assurance

MSAA's Sensor Reliability Coordinator proves functional security coverage. It complements the Service Watchdog and does not replace it.

## Responsibility boundary

| Component | Question answered | Authorized actions |
| --- | --- | --- |
| Service Watchdog | Is an installed, allowlisted launchd component alive and integrity-valid? | Validate plist/binary identity; execute bounded bootstrap or kickstart requests. |
| Sensor Reliability Coordinator | Is each sensor initialized, authorized, receiving, processing, delivering, and preserving the telemetry behind its claimed capability? | Evaluate evidence; correlate dependencies; run safe probes; request an allowlisted recovery; verify and observe recovery. |

The coordinator never restarts arbitrary processes. A recovery request contains a fixed sensor identifier and stable reason code, is written to a root-owned request directory, and is executed only after the watchdog revalidates the target plist and binary. Existing restart budgets and crash-loop suppression still apply.

## Runtime architecture

```text
GUI / sensors CLI
        |
        v
SensorReliabilityCoordinator
  | provider pool (bounded checks and timeouts)
  | evaluator (dimensions, score, hysteresis)
  | dependency propagation and root-cause grouping
  | recovery policy / circuit breaker / restart budget
  | post-recovery functional probe and stabilization
        |
        +--> SensorHealthStore (current, transitions, incidents, recovery)
        |
        +--> allowlisted request --> Service Watchdog --> launchd
```

`com.mac-audit-agent.sensor-health` runs a periodic one-shot cycle. The Service Watchdog treats a fresh completed cycle—not a transient PID—as the manager's liveness proof. Health providers run in a bounded worker pool so one broken provider does not prevent other sensors from being evaluated.

## State model

The public vocabulary is stable and machine-readable:

`UNKNOWN`, `INITIALIZING`, `HEALTHY`, `HEALTHY_IDLE`, `HEALTHY_WITH_WARNINGS`, `HIGH_LOAD`, `DEGRADED`, `IMPAIRED`, `BACKPRESSURED`, `STALE`, `RECOVERING`, `STABILIZING`, `FAILED`, `DISABLED`, `UNAVAILABLE`, `UNSUPPORTED`, `PERMISSION_BLOCKED`, `CONFIGURATION_ERROR`, `DEPENDENCY_FAILED`, `RATE_LIMITED`, and `MAINTENANCE`.

Each snapshot separately records process, collection, processing, delivery, storage, dependency, permission, configuration, and ruleset health. A healthy process dimension cannot override a failed processing or storage dimension.

Overall platform state is coverage-driven. A failed critical sensor dominates the platform result; healthy optional enrichment cannot average it away. Independent failure domains retain independent status.

## Functional evidence contract

Every provider implements `SensorHealthProvider`:

```python
def sensor_id() -> str
def health_snapshot() -> SensorHealthSnapshot
def dependencies() -> list[SensorDependency]
def perform_self_test() -> SelfTestResult
def recover(reason: RecoveryReason) -> RecoveryResult
```

The required snapshot includes:

- identity, version, instance, PID, initialization and process state;
- process, collection, processing, delivery, and persistence timestamps;
- received, processed, delivered, persisted, ignored, filtered, dropped, failed, duplicate, and rejected counters;
- queue depth/capacity, peak/average depth, oldest age, ingestion/processing/drop rates, and sustained backpressure duration;
- latency, worker progress, error and restart counts;
- dependency and permission states;
- configuration and ruleset hashes/state;
- capabilities, lost/retained coverage, fallback mechanism, and remediation;
- CPU, RSS trend, threads, descriptors, database/IPC latency, disk reserve, and other bounded resource metrics when available.

Missing functional evidence results in `UNKNOWN`, `STALE`, or a more specific degraded state. It never defaults to healthy.

## Freshness and event flow

Policies are typed and centrally validated. Sensor-specific overrides define expected idle windows and latency/loss thresholds. An intermittent sensor may be `HEALTHY_IDLE` only when a recent safe synthetic probe proves its path. A stale source without successful proof becomes `EVENT_STREAM_STALE`.

Pipeline progression is evaluated across collection, processing, delivery, and persistence. Examples:

- pending queue plus frozen processing heartbeat: `PROCESSING_STALL`;
- processed count advancing while delivery is stale: `DELIVERY_STALL`;
- processed count advancing while persistence is stale: `PERSISTENCE_STALL`;
- dropped count/rate above policy: `EVENT_LOSS`;
- sustained queue pressure: `QUEUE_BACKPRESSURE`.

Intentional filtering is accounted separately from loss.

## Native Endpoint Security telemetry

The native sensor health record now includes monotonically increasing received, processed, delivered, dropped, and failed counters; collection/processing/delivery activity times; queue depth/capacity; and peak depth. Kernel sequence gaps and bounded-queue rejection remain explicit loss evidence.

Endpoint Security collection and ransomware downstream analysis are distinct capabilities. Raw collection may remain available while ransomware persistence or correlation is impaired. The dashboard must not present fallback metadata observation as Endpoint Security parity.

## Safe self-tests and canaries

Self-tests are tiered:

- startup readiness;
- periodic lightweight checks with host-specific jitter;
- manual operator tests;
- post-recovery validation;
- extended tests reserved for scheduled or manual diagnostics.

The Endpoint Security provider creates only a uniquely tagged file in an MSAA-controlled temporary directory, performs create/write/rename/delete, and starts `/usr/bin/true`. It attempts to prove counter progression and removes the temporary directory. Canary identifiers are internal, never malicious findings, and never affect the security score.

SQLite checks use bounded read-only queries during normal cycles. Expensive integrity checks are reserved for startup, suspected corruption, maintenance, or explicit diagnostics.

## Recovery policy

Recovery proceeds from observe/retry through reconnect, reinitialize, worker restart, sensor restart, watchdog request, and operator action. The selected action is reason-specific.

Permission revocation, missing entitlements, invalid signatures, unexpected configuration changes, disk pressure, and duplicate singleton instances are not automatically “fixed.” They require an operator or a separately authorized installation workflow.

Each sensor has:

- a restart budget and rolling time window;
- exponential backoff with jitter;
- a `CLOSED`, `OPEN`, or `HALF_OPEN` circuit breaker;
- a post-action functional probe;
- a visible `RECOVERING` state;
- a multi-sample `STABILIZING` window before returning to healthy.

A successful kickstart alone is never proof of recovery.

## Hysteresis, incidents, and root cause

Noncritical degradation normally requires consecutive failed samples. Recovery requires more consecutive successful samples. Immediate integrity, permission, process-death, overflow, duplicate-instance, and restart-loop conditions bypass delay where appropriate.

One active incident is maintained for the same sensor/reason/root cause. Repeated observations update duration, occurrence count, and metrics. A changed cause, higher severity, additional capability loss, complete failure, or recovery creates a meaningful transition.

Shared dependency failures are grouped. For example, one privileged-helper failure may be the parent cause for multiple degraded sensors while unrelated network or persistence sensors remain healthy.

## Persistence and forensic disclosure

Sensor health uses the existing MSAA SQLite database with dedicated tables:

- `sensor_health_current`;
- `sensor_health_history`;
- `sensor_health_incidents`;
- `sensor_recovery_actions`;
- `sensor_dependency_health`;
- `sensor_health_summaries`;
- `sensor_manager_state`.

Transitions—not one row per second—are retained in a SHA-256 hash chain. Current snapshots and periodic summary state support availability, degradation duration, incident counts, MTTR, MTBF, and degradation-budget reporting without unbounded high-frequency rows.

Diagnostics exports include sanitized status, recent transitions, dependencies, and recovery history. HTML, DOCX, XLSX, and JSON are supported. Credentials, tokens, private keys, arbitrary event contents, and unrelated user data are excluded.

Incident/evidence exporters can use health history to disclose coverage during the incident window. A partial interval must remain visible rather than being summarized as complete evidence.

## Maintenance and updates

Maintenance requires a reason, initiator, start time, and bounded timeout. It expires automatically. It may describe expected upgrade or migration interruption but cannot permanently suppress failures.

Managed configuration and ruleset updates should use validate-before-activate and atomic replacement. Automatic rollback is restricted to explicitly managed MSAA state and must retain the failed candidate and recovery evidence. Host policy or macOS permission changes are never silently rolled back.

## CLI

```bash
msaa sensors status --json
msaa sensors status --verbose
msaa sensors test --json
msaa sensors test endpoint_security --json
msaa sensors history endpoint_security --json
msaa sensors dependencies --json
msaa sensors recover endpoint_security --json
msaa sensors diagnostics --output sensor-health.html --json
```

Manual privileged recovery still follows administrator authorization and the allowlisted watchdog boundary.

## Adding a sensor

A new sensor is incomplete until it:

1. declares its identity, criticality, capabilities, dependencies, singleton behavior, and failure domain in `assets/sensor_manifest.json`;
2. implements the provider contract and bounded timeout behavior;
3. reports layered heartbeats and event progression counters;
4. distinguishes filtering, rejection, failure, duplication, and unintended loss;
5. declares a validated policy override only where defaults are inappropriate;
6. provides a harmless self-test or explicitly explains why functional proof is unavailable;
7. defines targeted recovery and operator-only conditions;
8. maps each lost capability to retained coverage and plain-language remediation;
9. provides normal, stall, stale, backpressure, loss, dependency, permission, rules, restart, duplicate, resource, and recovery tests;
10. proves health events and diagnostics contain no secret or unrelated content.

Dynamic registration is compared with the expected manifest. A required module that never registers becomes a visible failure rather than disappearing from the inventory.

## Standards context

The design supports continuous monitoring, auditability, resilience, least privilege, failure isolation, and detection-coverage concepts used in NIST, CIS, MITRE ATT&CK, and defensive cyber operations guidance. These are engineering references. MSAA does not claim certification, approval, or endorsement by those organizations.
