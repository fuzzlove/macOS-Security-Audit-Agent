# Security Control Monitor Architecture

The pipeline is: registered control → bounded collector or native signal → normalized snapshot → material diff → authorization evaluation → incident-risk assessment → redaction → chained evidence transaction → durable alert queue → UI and native delivery attempts → watchdog records.

Polling provides deterministic reconciliation but is not treated as the only future source. FSEvents is a change signal and must trigger recollection; gaps require a scoped rescan and durable health event. Endpoint Security data must arrive from a signed native system extension and authenticated native service over bounded, versioned IPC. Python must not perform Endpoint Security callbacks or claim connectivity that the native sensor has not established.

Collection commands use absolute allowlisted executables, controlled environment variables, timeouts, bounded output, `shell=False`, and structured failures. Raw evidence and display summaries are separated. Secrets and control characters are removed before persistence, logs, export, or UI rendering.

Events use time-prefixed collision-resistant identifiers, UTC, canonical JSON, SHA-256 record chaining, WAL, synchronous transactions, and restrictive database permissions. Chain failure must be surfaced as an integrity failure; the store never silently repairs evidence.
