# Failure modes and recovery

WAL transactions recover committed receipts, aggregates, suppressions, and notification counters without replaying first notifications. Queue entries are idempotent by event/reason. Integrity verification checks event and administrative chains on health review or operator request. Notification failures change durable queue state and record only an error digest.

SQLite operational/storage failure returns a degraded decision, activates a bounded emergency memory buffer, and writes a sanitized digest receipt to a mode-0600 size-bounded fallback journal. It does not recursively submit a logging-failure event through the failed store. Recovery creates one bounded audit record when authoritative writes resume. The emergency journal is a last-resort availability mechanism: rotation reduces fidelity, it is not chained with the unavailable database, and it requires incident review.

System deployment must use the privileged component to establish the database directory and suggested 0750/0640 ownership. The source-mode adjacent key/fallback files use 0600. Do not silently change ownership from an unprivileged process.
