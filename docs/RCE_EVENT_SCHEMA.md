# RCE event schema

Version 1.0 is defined by `schemas/rce-event.schema.json` and typed by `rce_monitor.models`. Severity expresses impact; confidence expresses evidentiary strength. They are never combined. Runtime classes, health classes, review states, and CVE relationship types are fixed enumerations.

Candidates start `OPEN`; no detector can create `FALSE_POSITIVE`. The immutable first-occurrence payload contains observed facts, inference basis, contradictions, assumptions, unknowns, evidence references, rules, sensor health, CVE correlations, and redaction status. Group counters and review history are separate. A CVE object always records source hash/retrieval date plus matching, non-matching, and unknown criteria.

`CONFIRMED_REMOTE_CODE_EXECUTION` requires explicit reviewed evidence and is rejected as a heuristic initial state.

`injection_analysis` contains the named technique or stable `MSAA-PI-UNKNOWN-<digest>` investigation identifier, sophistication, exact verified/supporting/contradictory signals, source and target identities, unknowns, confidence basis, and evidence plan. An unsigned signature is context only and never establishes injection.
