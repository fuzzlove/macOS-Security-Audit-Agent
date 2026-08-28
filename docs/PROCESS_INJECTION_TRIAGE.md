# Process Injection Triage

For every candidate, verify:

1. Source and target process identity, start time, hash, signer, Team ID, package, path, user, session, and parent chain.
2. Exact task/handle access, rights, memory operations, addresses, protection history, target threads, start provenance, and loader/module state.
3. Whether in-memory image/module content matches its backing file and declared identity.
4. File, IPC, network, child-process, persistence, privilege, and RCE activity in the correlation window.
5. Whether an approved debugger, profiler, endpoint tool, accessibility component, crash reporter, managed runtime, anti-cheat, compatibility component, or maintenance window explains the observations.
6. Any deviation from that approved profile.
7. Sensor permissions, entitlement, queue loss, schema, clock, sleep/restart, protected-process, and enrichment gaps.
8. Evidence/custody hashes before containment or disposition.

Use controlled conclusions. Behavior consistent with a technique does not establish malicious intent or attribution.
