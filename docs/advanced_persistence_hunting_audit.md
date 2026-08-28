# Advanced Persistence Hunting architecture audit

MSAA extends its existing Persistence Intelligence subsystem; it does not create a parallel scanner or event store.

## Existing coverage retained

The scanner registry already covers launchd, Background Task Management artifacts, scheduled jobs, shell startup files, authorization plugins, legacy autoruns, dynamic-loader declarations, application autorun plug-ins, browser persistence, profiles, certificate trust, extensions, privileged helpers, path hijacking, support directories, users/groups, and TCC indicators. Existing baseline comparison records added, removed, modified, hash, permission, owner, signature, loaded, and disabled-state changes. Continuous monitoring uses `BackgroundMonitorEvent`, the shared SQLite event pipeline, CVSS-colored visible alerts, and existing persistence report/UI adapters. Remediation remains confirmation-driven, symlink-refusing, evidence-first quarantine.

## Enhancements

- Dedicated SSH authorized-key/configuration detection with content-safe fingerprints.
- Bounded AppleScript automation inspection and behavior extraction.
- Launchd target signature, Team ID, developer identity, and hash enrichment.
- Mechanism-specific posture deductions and CVSS-enriched persistence events.
- Identity-bound user trust records that invalidate when hash, path, bundle ID, or Team ID changes.
- First/last-seen continuity across baseline comparisons.

## Known evidence boundaries

- Responsible process/parent attribution is populated when Endpoint Security/native event evidence supplies it; periodic inventory cannot truthfully reconstruct a historical writer.
- Whole-application inventory remains authoritative in the existing Not Signed service. Persistence Hunting assesses referenced launchd targets and does not duplicate that inventory.
- `sfltool dumpbtm` output varies by macOS release and is not treated as authoritative without a versioned parser fixture; existing BTM artifact inventory remains the safe fallback.
- Full Disk Access and root-owned locations can produce partial coverage. The scanner reports this rather than claiming clean state.
- Hash reputation is supported locally. No external reputation verdict is invented when a service or network is unavailable.
- Framework mappings are supporting evidence and do not independently certify NIST, CIS, DoD, or CMMC compliance.
