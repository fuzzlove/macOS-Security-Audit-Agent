# Suspected Remote Code Execution

MSAA records exploitation-like consequences before exploitation is proven. The primary investigation event is `SUSPECTED_REMOTE_CODE_EXECUTION`; this is an evidence-preservation classification, not a compromise verdict.

## Data flow

```text
macOS/native sensors and bounded fallbacks
  -> redaction and raw-observation spool
  -> exploit primitive extraction
  -> 5s / 30s / 2m / 5m correlation
  -> explainable confidence calculation
  -> immutable RCE event and normalized evidence
  -> Host IDS / Investigation Priority / Alert Center / Flight Recorder
```

The raw observation is stored before enrichment. A parser or enrichment failure changes the observation state to `ENRICHMENT_FAILED`, produces health telemetry, and does not delete the base record. The service is monitor-only and never terminates a process or disables a macOS security control.

## Classification and confidence

The engine separates security severity, evidence confidence (0–100), classification, and analyst disposition. Its classifications are:

- `CONFIRMED_OR_HIGH_CONFIDENCE_RCE`
- `PROBABLE_RCE`
- `SUSPECTED_RCE`
- `RCE_LIKE_MEMORY_CORRUPTION`
- `SUSPICIOUS_CRASH_EXPLOIT_PRECURSOR`
- `BENIGN_OR_EXPECTED_CRASH`
- `INSUFFICIENT_EVIDENCE`

Memory faults, stack/heap corruption, control-flow anomalies, executable memory, write-to-execute transitions, related process/shell creation, temporary or unsigned execution, network activation, and sufficiently supported local CVE similarity each contribute a recorded amount. Multi-stage correlation requires independent primitive categories. One weak observation cannot produce a critical result.

Approved JIT behavior, debugger attachment, recognized test/fuzzing harnesses, scoped analyst suppressions, and Research/Fuzzing/Development policy context reduce confidence. They never erase evidence. Unexpected post-crash execution continues to be evaluated. Temporal proximity is described as correlation, never causation.

## Privacy and platform boundaries

MSAA retains process identity and ancestry, code-signing state, hashes, bounded exception metadata, file metadata, and network endpoints when sensors provide them. It does not collect packet contents, keystrokes, document contents, secrets, or process environments for this feature. Commands and ancestry arguments are redacted before persistence. File contents are discarded. Register metadata from IPS reports is bounded to scalar fields and is only used when macOS supplies it.

Polling is explicitly reported as degraded. Missing process, file, network, memory, or crash telemetry is shown as `LIMITED` or `UNAVAILABLE`; missing telemetry is never interpreted as zero activity.

## Storage and reproducibility

Schema version 3 extends the existing hash-chained `rce_events` store with normalized reason evidence, exploit primitives, timeline entries, processes, memory indicators, file/network evidence, CVE relationships, sensor coverage, analyst dispositions, crash signatures, and the bounded ingest spool. Each event retains its model version, original classification/score, raw references, sensor coverage, and evidence gaps.

Identical crash signatures increment an occurrence counter and retain a bounded number of distinct representative raw observations. A different binary, exception, faulting module/instruction, stack signature, or crash signature remains distinct. Material score or classification escalation creates a new immutable event in the same correlation group.

Analyst disposition never replaces the original detection. Benign, fuzzing, debugger, and false-positive decisions require a reason/evidence reference and are appended to the review audit trail.

## CVE and ATT&CK context

CVE behavior similarity requires an approved local CVE record, at least three meaningful matching characteristics, and a similarity of at least 60%. The result states the percentage and explicitly does not claim that the CVE was exploited. Detection remains fully local and functional without CVE data.

ATT&CK mappings are added only when their supporting behavior is present—for example, a related shell for Command and Scripting Interpreter or a multi-stage memory-fault/execution sequence for Exploitation for Client Execution. A crash alone does not receive broad ATT&CK mappings.

## Benign demonstration

Run `msaa rce-monitor --db /path/to/test.sqlite3 demo-suspected-rce`.

The fixture executes no commands and contains no exploit payload. It synthesizes an `EXC_BAD_ACCESS`, a related non-interactive `/bin/sh`, a temporary unsigned executable observation, and outbound network metadata. The final event contains the requested structured reason codes and an ordered evidence timeline.

## Adding a sensor

Emit `TelemetryEvent` objects with timezone-aware `observed_at`, stable PID/PPID and user/session references, a source sensor name/version, only the metadata the sensor actually observed, a canonical evidence reference, and an explicit `sensor_coverage` map. Do not infer absent values. Privileged native collectors should send minimum structured telemetry through authenticated IPC; analysis and UI remain unprivileged.

Use `RCEMonitorService.ingest()` so the redacted raw observation is preserved before enrichment. Sensor threads must not update PySide widgets directly.
