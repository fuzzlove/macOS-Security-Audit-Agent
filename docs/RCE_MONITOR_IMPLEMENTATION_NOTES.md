# RCE monitor implementation notes

## Recovery inspection

The working tree contained isolated `suspicious_process_observed`, possible in-memory execution findings, process/network/persistence collectors, CVE Radar caches, bounded subprocess utilities, ATT&CK correlation, the shared monitor SQLite database, and an existing boot LaunchDaemon. No active, dedicated RCE daemon/schema/review workflow was found. Git history inspection failed with `fatal: bad object refs/remotes/origin/HEAD`, so deleted history could not be safely reconstructed.

Reused: existing LaunchDaemon lifecycle, system/user process split, fixed executable subprocess pattern, SQLite database, monitor state/logging, package inventory concepts, and explicit degraded sensor semantics. Superseded: ad-hoc narrative-only suspicious-process findings for RCE decisions and naive generic version comparison. No prior code was blindly restored.

## Decisions and assumptions

The RCE analyzer is embedded in the existing system daemon to avoid a second privileged runtime. Dedicated tables preserve typed evidence/reviews while sharing the database and installer. The privileged daemon never retrieves feeds. Configuration defaults to high sensitivity and monitor-only. Root is the default management identity. Endpoint Security is assumed unavailable until entitlement and signed adapter evidence exist.

## Limitations and remaining work

Polling is partial telemetry. File/network correlation hooks accept structured evidence but complete live correlation awaits an entitled collector. Application/container manifest inventory and automatic approved-feed transformation are not yet wired into the daemon. Suppression storage is implemented; automatic matcher application/export reporting remains future work. Retention settings are validated but automated evidence deletion is intentionally not enabled because signed retention-boundary evidence is not yet implemented. LaunchDaemon installation was not performed on the development host. Legal, privacy, security, and authorizing officials must review telemetry scope, retention, management identities, feed approval, and response procedures.

The process-injection classifier recognizes eight macOS technique families and assigns stable identifiers to unmatched multi-signal combinations. The fallback daemon does not itself produce reliable Mach task/thread API telemetry; those classifications become operationally useful when an entitled native sensor or another approved structured sensor supplies provenance. Evidence snapshots are explicit CLI actions for an existing DFIR case. PCAP remains a separately approved manual workflow.

## Validation record (2026-07-19 development host)

- `pytest tests/test_rce_monitor.py`: 16 passed.
- RCE plus EULA/PF integration selection: 20 passed.
- Existing monitor integration selection: 5 passed, 222 deselected.
- `compileall` for new modules and integration points: passed.
- Synthetic benchmark, 5,000 events: 2.372499 seconds, 2,107.48 events/second, 0.140537 ms mean and 0.811108 ms maximum analysis latency, 1,409,024 database bytes, one grouped record, 2,048 bounded queue depth, zero reported drops, valid chain. macOS 26.5.2 x86_64, CPython 3.13.14. `ru_maxrss` was 27,111,424 platform units; CPU user time was 1.564079 seconds. CVE latency was not measured because no approved CVE performance fixture was supplied.
- The complete background-monitor file was attempted and produced pre-existing launchd/UI expectation failures, then was interrupted during long-running UI paths before a final count. The entire repository suite was therefore not established as passing.
- Ruff was configured but unavailable in the active virtual environment. Git diff/history checks were blocked by missing/corrupt Git objects (`refs/remotes/origin/HEAD` and object `82da88488189f1f62c92948ab5d096b1ec2a1f5b`).
