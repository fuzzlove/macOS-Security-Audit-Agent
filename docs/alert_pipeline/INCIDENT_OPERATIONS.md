# Incident-response operations

Use `msaa alerts status|health`, `active`, `history`, `show <alert-id>`, `export --output <mode-0600-path>`, and `verify-integrity`. The Alert Center provides consolidated active incidents, affected-entity counts, queue/cardinality/storage state, integrity and fallback state, bounded event drill-down, suppression review, and a redacted review export.

For a critical incident: preserve evidence before remediation; record the incident/ticket; inspect severity/material changes and source/entity expansion; verify integrity; review overflow, compaction, queue, logging-fallback, and storage-pressure evidence; export the review; preserve the database, WAL, SHM, integrity key, and fallback journal together using approved acquisition procedures. Do not copy a live database without its WAL/SHM state.

Frequency is never a whitelist signal. Acknowledgment consolidates presentation and suppression affects notification eligibility only; neither erases receipts. If fallback logging is active, treat it as reduced forensic fidelity, stabilize storage, preserve the fallback file, verify recovery, and reconcile source evidence. If integrity fails, stop ordinary cleanup, preserve the affected files and system logs, and escalate to the incident-response owner.
