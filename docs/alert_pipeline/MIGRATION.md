# Migration notes

Schema version 1 is created idempotently by `ensure_resilient_alert_schema` and recorded in `resilient_alert_metadata`. It adds separate security-event, aggregate, notification, administrative-audit, suppression, compaction, action-idempotency, and bounded-metric tables. Existing monitor, trace, delivery, acknowledgment, and action tables remain readable. New receipts pass through the resilient ledger before a compatibility `background_monitor_events` row.

Startup rejects unsupported event/config schema versions. Future database changes must add ordered transactional migrations, pre/post schema assertions, rollback notes, and fixture databases for every supported source version; editing the metadata version alone is prohibited. Rollback requires stopping writers and restoring a complete pre-migration database/WAL/SHM/key backup. Deleting only new tables destroys audit evidence and is not an approved rollback.
