# Process Injection Evidence

Tier 0 preserves event, host/boot, sensor, source/target identity, signing/hash metadata, rules, primitives, raw references, and data gaps. Tier 1 adds bounded process trees, `vmmap`, module/open-file/socket metadata, thread samples, file/network context, and relevant logs when permitted. Tier 2 targeted artifacts and memory are disabled by default and require explicit deployment authorization. Tier 3 remains an approved incident-response integration, never automatic broad acquisition.

Bundles contain an event summary, normalized primitives, graph/timeline, process tree, map comparisons, thread/file/network evidence, ATT&CK snapshots, template/variant/novelty comparisons, benign explanations, missing/contradictory evidence, sensor coverage, review history, collection failures, hashes, and a custody manifest. Artifact access and verification are audited. Changed manifests fail verification.

Evidence is tamper-evident through hashes and custody chaining, not tamper-proof. Encryption-required deployments fail closed if no approved provider is configured. Full process memory, protected-process memory, credentials, tokens, cookies, private keys, unrelated documents, and broad packet payloads are not collected by default. Retention and classification require deployment review.
