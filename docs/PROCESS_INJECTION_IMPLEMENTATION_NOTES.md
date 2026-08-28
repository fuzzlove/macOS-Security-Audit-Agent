# Process Injection Implementation Notes

Existing functionality reused: the RCE LaunchDaemon integration, bounded process polling, `vmmap` heuristics, unsigned-process and signing inventory, dylib-hijack analysis, SQLite/WAL storage, evidence repository/custody chain, local ATT&CK STIX provider, review/suppression tables, redaction, health events, and CLI dispatch.

Replaced or extended: the first signal-set classifier now feeds a platform-neutral primitive graph and versioned template/lineage engine. PID-only relationships are rejected in favor of boot/start identities. Generic unsigned/RWX evidence is never sufficient alone. Ad-hoc ATT&CK claims are rejected when the configured dataset cannot validate them.

Git history remains unavailable because repository refs/objects are corrupt; no deleted code was restored. Schema v2 migrates v1 in place and adds primitive, research, benign-context, evidence-bundle, and access-audit tables.

Implemented: deterministic normalization, stable identity, graph correlation, six macOS templates, partial/variant/novel analysis, footprint disclaimers, separate scores, sequential research IDs, benign catalog, evidence bundles, Tier 2 denial, CLI views, health status, schemas, fixtures, tests, and docs.

Partial: live graphs currently depend on structured sensor events; polling does not produce Mach memory/thread primitives. Benign matching presently evaluates expiry and primitive profile, while all identity/profile fields are stored for further enforcement. Suppression occurrence matching/reopening automation remains incomplete. Evidence encryption has a fail-visible policy boundary but no configured encryption provider. ATT&CK history is captured in event comparisons when supplied, but automatic dataset archival is not implemented.

Unsupported: Windows/Linux collectors, full memory acquisition, automatic PCAP, actor attribution, ML scoring, rule auto-promotion, and automatic external submission. Installation and privileged evidence collection were not executed on this host. Security, privacy, legal, system-owner, evidence-retention, and authorizing-official review remain required.

## Validation record

- Focused process-injection/RCE/EULA/PF integration: 44 passed in 2.01 seconds.
- Existing daemon regression selection: 5 passed, 222 deselected in 2.87 seconds.
- Rule validation: 6 structurally valid templates; promotion remains human-gated.
- Python compilation of the new analytics, bundle, CLI, repository, analyzer, and service modules: passed.
- JSON parsing for configuration, event/bundle schemas, and replay fixtures: passed.
- Full repository attempt: interrupted after 146.23 seconds with 94 passed, 1 unrelated pre-existing Apple diagnostics exporter failure, and 16 UI warnings. The failure was `test_apple_evidence_package_exports_manifest_hashes_and_review_warning`; no claim of a passing full suite is made.
- Synthetic benchmark on macOS 26.5.2 x86_64, CPython 3.13.14: 30,000 primitive events / 10,000 graphs in 1.518131488 seconds; 19,761.13 raw events/second; mean normalization 0.020596 ms; graph correlation 0.060510 ms; template/novelty analysis 0.069942 ms; zero reported event loss; CPU user time 1.617622 seconds; `ru_maxrss` 21,204,992 platform units. Storage, privileged evidence enrichment, and restart timing were not measured by this in-memory benchmark.
