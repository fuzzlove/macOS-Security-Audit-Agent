# Event schema

`SecurityEvent` schema version 1 contains stable event/rule/source identities, UTC and monotonic timestamps, host/user/process/network/object context, action/outcome, bounded attributes, MITRE/CVE/tag lists, correlation/incident IDs, fingerprint/material digests, suppression disposition, and integrity fields. Unknown safe optional data belongs in bounded `attributes`; unknown schema versions fail closed.

Identifiers, paths, names, addresses, and list members have explicit length/count bounds. Attributes reject excessive nesting, maps, arrays, bytes, and oversized canonical messages. Password/API-key/token/cookie/session/authorization/private-key fields and recognizable credential text are redacted before persistence. Raw command environments, credentials, unrestricted command lines, and binary payloads are not accepted. Rejected-event audit entries store only bounded category and source/event-ID digests, not the attacker payload.
