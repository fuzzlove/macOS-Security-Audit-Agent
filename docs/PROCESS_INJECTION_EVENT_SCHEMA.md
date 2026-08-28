# Process Injection Event Schema

The versioned RCE schema now includes event classification, boot identity, source/target process and thread context, sensor reliability and gaps, normalized primitives, behavior-graph reference, separate assessment dimensions, known-technique comparisons, nearest technique, lineage/novelty analysis, footprint similarities, benign explanations, evidence tier/failures, research/case/bundle identifiers, review, and suppression state.

Graph edges preserve relationship, source, target, time, sensor reliability, raw reference, thread/region identity, and attributes. Technique comparisons include ID/name/version, relationship type, shared/missing/different primitives, contradictions, similarity, confidence, data source, retrieval date, and validation status. See `schemas/rce-event.schema.json` and `schemas/process-injection-evidence-bundle.schema.json`.
