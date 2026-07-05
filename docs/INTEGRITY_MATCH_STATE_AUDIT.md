# Integrity Match State Audit

## Flow

`manifest file -> parser -> metadata comparison -> file verification -> verification result -> Operational Health -> UI/report payload`

Operational Health checks the stored source baseline first. If no stored baseline exists, it now verifies the on-disk `msaa_integrity_manifest.json` at the detected source root before reporting `unknown`.

## Match Requirements

A manifest can return `verified` when:

- manifest exists and is readable
- `trust_state == trusted`
- `source_type` is the selected mode or a compatible legacy mode
- `app_version` matches when provided
- `build_id` matches when both manifest and current build IDs are provided
- `git_commit` matches when both sides provide it
- required files exist
- required file SHA-256 hashes match
- required runtime permission/owner metadata matches when recorded
- no unexpected executable extra file is found

## Non-Blocking Conditions

The following must not create a broken or stale result by themselves:

- optional git metadata unavailable
- optional build ID missing on one side
- dirty source checkout when required file hashes still match
- changed logs, reports, settings, databases, caches, snapshots, or generated output
- optional warnings without required-file mismatches

## Diagnostic Fields

The verifier now carries:

- `result_id`
- `checked_at`
- `manifest_path`
- `source_type`
- `trust_state`
- `manifest_app_version`
- `current_app_version`
- `manifest_build_id`
- `current_build_id`
- `manifest_git_commit`
- `current_git_commit`
- `manifest_hash`
- `cache_valid`
- `matched_count`
- `mismatched_count`
- `missing_count`
- `extra_count`
- `skipped_count`
- `health_impact`

## Where False Status Was Introduced

The stale/broken-looking behavior was introduced in source-tree verification and Operational Health interpretation:

- source-tree verification returned `unknown` when git metadata was unavailable before checking matching hashes
- dirty source state incremented `skipped_count`, which could downgrade a file-hash match
- Operational Health did not have a `verified_with_warnings` mapping
- legacy source-integrity schema drift could be interpreted as file drift rather than stale trust metadata
- Operational Health did not use a valid on-disk source manifest when the legacy DB baseline was missing

## Corrected Final States

| Condition | Verifier status | Health impact |
|---|---|---|
| Trusted manifest and required hashes match | `verified` | `healthy` |
| Trusted manifest matches with non-critical warnings | `verified_with_warnings` | `healthy` |
| Missing manifest | `unknown` | `degraded` |
| Draft manifest | `draft` | `degraded` |
| App/build/git conflict where both sides provide values | `stale` | `degraded` |
| Required file hash mismatch | `modified` | `broken` |
| Required file missing | `modified` | `broken` |
| Verifier exception | `failed` | `degraded` unless security assurance is impossible |

## Current Result

When a trusted integrity manifest matches the current build and required file hashes match, MSAA reports:

- Integrity Status: `verified`
- Operational Health Impact: `healthy`
- Manifest Match: yes
