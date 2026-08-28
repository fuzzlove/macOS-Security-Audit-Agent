# Behavioral Telemetry

Behavioral Telemetry is MSAA's local, explainable User and Entity Behavior
Analytics subsystem. It models security-relevant host and user activity; it is
not a productivity monitor and does not infer intent. An unusual observation is
a reason to investigate, not proof of maliciousness.

## Data flow and reuse

```text
Existing macOS/MSAA sensors
        |
        v
canonical BackgroundMonitorEvent + resilient alert ledger
        |
        +--> primary detection and evidence processing (never blocked)
        |
        v
bounded TelemetryManager queue
        |
        v
TelemetryNormalizer -> privacy minimization -> TelemetryAggregator
        |
        v
local host/user/time-cohort baseline -> anomaly explanation
        |
        v
BehavioralCorrelationEngine
        +--> Investigation Priority
        +--> one correlated Alert Center event when policy warrants
        +--> bounded Flight Recorder evidence-reference snapshot
        +--> Dashboard / Sensor Health / Reliability / CLI / UI
```

The subsystem extends canonical `background_monitor_events`; it does not create
a second raw sensor store. `telemetry_event_links` contains normalized numeric
features and references back to canonical evidence. Alert Center continues to
consume the resilient alert pipeline. Flight Recorder continues to consume the
canonical event timeline. Behavioral correlation publishes at most one alert
for an open incident and its generated event is excluded from telemetry
normalization to prevent feedback loops.

Primary modules are in `mac_audit_agent/telemetry/`:

- `manager.py`: bounded, asynchronous secondary processing and health metrics.
- `normalizer.py`: canonical event mapping, stable references, coverage, and
  training eligibility.
- `privacy.py`: argument redaction and bounded data minimization.
- `aggregator.py`: five-minute host and user buckets with temporal/context
  cohorts.
- `baseline.py`: versioned robust local baselines.
- `anomaly.py`: coverage-aware, multi-signal, explainable scoring.
- `correlation.py`: user/entity/window incident grouping and evidence freeze.
- `storage.py`: additive SQLite migration and query repository.
- `synthetic.py`: benign deterministic workload and incident generators.

## Privacy model

Behavioral Telemetry never requires keystrokes, mouse movement, clipboard
contents, document or message contents, page contents, or employee activity
time. It stores pseudonymous host, user, process, path, destination, and domain
references for aggregation. Display-name resolution belongs at presentation
boundaries.

Command-line metadata is optional and redacted before persistence. Recognized
password, token, secret, Authorization/Bearer, API-key, AWS-key, and private-key
patterns are replaced with redaction markers. Mappings, arguments, entity sets,
and evidence-reference sets are size bounded. A new sensor must not place secret
values into feature names or entity identifiers.

Privilege is separated: privileged collectors emit the minimum authenticated
structured event through existing MSAA sensor boundaries. Aggregation, baseline
calculation, charting, and correlation run without requiring the GUI or analytics
worker to be root.

## Feature definitions

Normalized values are numeric and schema-versioned. Current stable features
include:

| Dimension | Examples |
|---|---|
| Process | `process_exec_count`, `unique_process_count`, `first_seen_process_count`, `unsigned_process_count` |
| Network | `network_connection_count`, `unique_destination_count` |
| DNS | `dns_query_count`, `unique_domain_count`, `dns_resolver_change_count` |
| Filesystem | `filesystem_event_count` |
| Persistence | `persistence_change_count` |
| Authentication | `authentication_event_count`, `authentication_failure_count`, `new_administrator_count` |
| Privilege | `privileged_execution_count` |
| Security configuration | `security_setting_change_count` |
| Software | `software_installation_count` |
| External device | `external_device_event_count` |
| Sensor/security tool | `sensor_security_tool_event_count` |
| Application | `application_event_count` |

Each ingress receipt contributes one event. Canonical duplicate occurrence
counters are not re-added because doing so would cause quadratic growth.

## Buckets, cohorts, and coverage

The default bucket is five minutes. Each event updates both its stable user
bucket and the host bucket. Baselines are not shared across Macs or users.
Temporal cohorts distinguish weekday/weekend and local hour. Context cohorts
distinguish steady state, startup, wake grace, maintenance, and research mode.
Maintenance and research buckets are excluded from the normal baseline by
default. Sleep produces no inactivity finding; wake and startup bursts are not
compared directly with steady state.

Coverage is stored per dimension as `VALID`, `REDUCED`, `UNKNOWN`, or
`UNAVAILABLE`. An unavailable sensor produces a missing value, never zero.
Anomaly analysis skips unavailable dimensions and reduces overall confidence.

## Baseline mathematics

MSAA begins with interpretable robust statistics:

- median;
- median absolute deviation (MAD);
- p05, p25, p50, p75, and p95;
- robust spread derived from MAD and interquartile range;
- categorical first-seen/entity frequency context.

Distributions are not assumed to be Gaussian. A feature is compared against the
matching host, user, temporal, and operational context. The all-time cohort is a
fallback. Confidence progresses from `LEARNING` through `LOW_CONFIDENCE`,
`ESTABLISHED`, and `MATURE`; policy profiles can configure sample guidance.
Low-confidence statistical scores are capped unless independent deterministic
security evidence warrants escalation.

Baseline versions record training bounds, eligible/excluded bucket counts,
feature schema, behavior model, reason, and creation time. Suspicious,
simulated, critical, known-malicious, research, and maintenance observations are
excluded or down-weighted through `baseline_training_eligible`. Manual rebuilds
create a new version boundary and audit record; they do not erase anomalies.

## Scoring and explanation

An anomaly score is 0–100 and remains distinct from security severity and
detection confidence. Robust deviation supplies the initial score. Multiple
feature deviations and additional context—first seen, unsigned/invalid signing,
download or temporary execution, privilege, and deterministic intelligence—add
bounded correlation weight. A rare event alone remains a modest observation.

Stable reason codes include process rate, first-seen executable, unsigned
execution, network rate, destination diversity, DNS rate/diversity, new resolver,
authentication failures, new administrator, privilege spike, persistence,
security configuration, software installation, and composite anomaly codes.

Every anomaly retains:

- observed value and comparable normal range;
- human-readable reasons and stable reason codes;
- anomaly score, security severity, and confidence;
- baseline, feature-schema, scoring-model, and policy versions;
- coverage state, related pseudonymous entities, and canonical evidence refs;
- operator disposition and recommendation.

Statistical scoring cannot reduce a deterministic high-confidence local IOC,
hash, or YARA result. Antiransomware remains responsible for ransomware
classification; Behavioral Telemetry contributes baseline context only.

## Correlation and evidence

Anomalies above the investigation threshold are grouped by user, process/entity,
and a bounded time window. Related process, network, persistence, and privilege
signals become one `behavioral_incident`. When serious context supports an
alert, correlation publishes one canonical event for the incident. Minor
anomalies remain in the Behavioral Telemetry timeline without creating alert
storms.

Crossing the investigation threshold creates a bounded Flight Recorder snapshot
of canonical event IDs around the anchor time. Evidence is referenced rather
than copied. The anomaly preserves baseline, feature, model, coverage, and
calculation data so a historical result can be explained later.

## Storage and retention

Additive tables are:

```text
telemetry_event_links
telemetry_buckets
telemetry_bucket_analysis
telemetry_baseline_versions
telemetry_baselines
behavioral_anomalies
behavioral_incidents
behavioral_evidence_snapshots
behavioral_entity_profiles
behavioral_feedback
behavioral_audit_trail
telemetry_runtime_state
```

Indexes follow actual time, user/time, feature/version, anomaly/incident, and
entity lookups. Raw normalized links have short retention, aggregates have
longer retention, unlinked anomalies follow anomaly policy, and incident-linked
evidence follows evidence policy. Canonical raw-event retention remains owned by
the canonical event service.

## Backpressure and failure behavior

Sensor persistence never waits for analytics. `TelemetryManager` uses a bounded
queue and bounded batches. Queue overflow records dropped telemetry and marks
Behavioral Telemetry degraded while primary detection continues. Event/entity
sets, correlation windows, chart result counts, and evidence snapshots are
bounded. Baselines are rebuilt on a maintenance interval or explicit request,
not by scanning 30 days for every event.

Health metrics include last raw event, bucket, baseline update and analysis;
received/aggregated/analyzed/anomaly counts; queue depth and peak; dropped
telemetry; processing latency; worker state; and errors. Sensor Health maps these
to aggregation, baseline, and anomaly capabilities. Missing telemetry is
reported as partial/unavailable, not normal.

Database lock/full/corruption, malformed events, invalid numeric fields, queue
overflow, worker exceptions, sensor loss, and clock changes must degrade
analytics without changing the result of canonical security-event storage.
Wall-clock evidence is timezone-aware UTC; durations and worker latency use
monotonic time.

## UI and CLI

The UI queries aggregated buckets only. It provides activity vs expected
baseline, normal range, threshold, evidence-linked markers, per-dimension
coverage, behavior timeline, detailed explanations, and audited operator
dispositions. The Dashboard shows one concise Behavior card.

```bash
msaa telemetry status
msaa telemetry summary --since 24h
msaa telemetry anomalies --since 7d --json
msaa telemetry baseline --user <stable-user-ref> --json
msaa telemetry baseline --rebuild --reason "approved role change"
msaa telemetry export --since 24h --output telemetry.json
msaa telemetry doctor --json
```

All analytics work offline. Network intelligence may enrich an incident when an
approved source is available, but no remote service is required.

## Adding a sensor contribution

1. Emit a canonical `BackgroundMonitorEvent`; do not call the baseline or UI
   directly.
2. Use a stable event type and structured metadata. Keep content and secrets out.
3. Add the event-to-feature mapping in `TelemetryNormalizer._features` and a
   stable reason code when the feature can generate deviations.
4. Identify the responsible sensor and explicit coverage. On loss, emit health
   evidence; do not emit zero-valued synthetic activity.
5. Set context (`maintenance_context`, `research_mode`, startup/wake) and
   `baseline_training_eligible` implications explicitly.
6. Add golden tests for normalized features, time/context cohort, expected
   baseline behavior, missing coverage, explanation, and correlation.
7. Validate that canonical ingestion succeeds when telemetry processing is
   stopped, full, locked, or malformed.

Never add UI-string parsing, unbounded raw payloads, a global cross-user model,
or a new alert schema for a sensor contribution.

## Test fixtures

`telemetry/synthetic.py` generates benign content-free profiles for a normal
workday, developer workstation, office user, service workload, research device,
process/network storms, authentication anomaly, persistence incident, and
ransomware-like file activity. `required_demonstration()` establishes historical
cohorts and then creates the mission's first-seen unsigned executable, process
burst, new destinations, persistence, and privilege sequence. Tests require one
correlated incident, one alert, and one preserved Flight Recorder context.
