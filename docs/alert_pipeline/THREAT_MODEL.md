# Threat model

## Adversaries and assets

Protected assets are detection availability, forensic receipt accounting, notification usefulness, aggregate/incident state, suppression policy, automated-response idempotency, integrity metadata, and operator trust. Relevant adversaries include untrusted event data, a noisy or compromised detector, a local unprivileged process, a malicious/compromised administrator, and a fully privileged/kernel attacker. The last can defeat endpoint-local evidence; this design only raises the cost and visibility of tampering.

## Implemented defenses

- **Exact duplicate flooding:** durable per-receipt sequence/digest accounting, one aggregate/card, threshold and monotonic periodic summaries, raw first/latest retention, explicit intermediate-body compaction.
- **Alert starvation:** P0/P1 priority classes and notification reserve prevent ordinary low-priority first occurrences from consuming every slot; retrieval is strict priority then FIFO.
- **False-alarm masking:** detector-specific identity/material digests; severity, confidence, outcome, user, hash, destination, and object changes create a new identity or bypass consolidation. Frequency never lowers severity or creates trust.
- **High cardinality:** bounded active fingerprints and source windows; low-priority excess enters bounded rule/source/priority overflow aggregates with original fingerprint digests and fidelity-reduction audits. Critical/protected identities bypass overflow.
- **Log/storage exhaustion:** logical quota and emergency reserve thresholds compact redundant low-priority bodies first while retaining protected raw records and all ledger rows. Health exposes pressure. Automatic archival/deletion is intentionally not implemented without an approved retention policy.
- **Malformed/injected data:** schema/type/size/depth/count validation, binary rejection, redaction, canonical serialization, parameterized SQL, bounded audit labels, and no shell/template evaluation. In-process producers inherit the service identity.
- **Suppression abuse:** exact fields only; wildcard/global/indefinite rules rejected; reason/ticket/authorizer/expiration required; duration bounded; ordinary protected suppression ignored; optional distinct approval identity; all matching evidence remains logged.
- **Time manipulation:** rate and periodic-summary windows use monotonic time; wall rollback creates a protected receipt. UTC remains explicit forensic/reporting time.
- **Tampering/restart:** keyed event and administrative chains, WAL transactions, persisted aggregates/suppressions/counters, event-ID idempotency, restart tests, and integrity review.
- **Notification/logging loops:** notification delivery is downstream and durable; errors store digests. Store failure uses a separate bounded fallback and does not recursively ingest through SQLite.
- **Repeated response:** action reservation keys cover policy, fingerprint, action, target, and incident. Duplicate reservations cannot execute twice.

## Trust-boundary limitation

Detectors calling the in-process API inherit the installed service identity; arbitrary local IPC ingestion is not exposed. A future socket/XPC producer must authenticate peer credentials, bind the verified PID/UID/code identity to a registered source, apply message framing limits before JSON decoding, and test spoofing before `source_authentication_enabled` can describe that transport. The configuration flag expresses required policy; it does not manufacture authentication for a transport that does not exist.
