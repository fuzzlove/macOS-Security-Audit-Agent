# Integrity Hashing Audit

## Summary

MSAA program integrity verification is implemented by `mac_audit_agent.integrity` and consumed by `mac_audit_agent.source_integrity` and `mac_audit_agent.operational_health`. The corrected behavior is evidence-based: MSAA only reports `verified` when current program/runtime files match a trusted manifest, and it never treats mutable operational data as source-code tampering.

## Hashing Functions

| Function | File | Purpose |
|---|---|---|
| `calculate_sha256(path)` | `mac_audit_agent/integrity/hasher.py` | Streams file content in chunks and returns SHA-256 |
| `collect_integrity_files(root, mode, exclusions)` | `mac_audit_agent/integrity/hasher.py` | Public deterministic sorted file collector after exclusions |
| `iter_integrity_files(root, exclusions)` | `mac_audit_agent/integrity/hasher.py` | Internal collector used by compatibility paths |
| `create_integrity_manifest()` | `mac_audit_agent/integrity/manifest.py` | Records stable files and metadata into a draft/trusted manifest |
| `verify_integrity_manifest()` | `mac_audit_agent/integrity/verifier.py` | Compares current files to an existing manifest |
| `verify_source_integrity()` | `mac_audit_agent/source_integrity.py` | Bridges legacy Operational Health source state to manifest verification semantics |

## Manifest Format

Primary fields:

- `manifest_id`
- `manifest_version`
- `trust_state`
- `source_type`
- `app_version`
- `build_id`
- `git_commit`
- `root_path`
- `file_entries`
- `excluded_patterns`
- `manifest_hash`

`trust_state=trusted` is required for verification. `draft`, `revoked`, `expired`, and `unknown` manifests cannot produce a verified result.

## Manifest Paths

| Mode | Expected manifest |
|---|---|
| Source tree | `./msaa_integrity_manifest.json` or stored source baseline |
| System runtime | `system_daemon_runtime`, runtime directory `integrity_manifest.json` |
| User notifier runtime | `user_notifier_runtime`, user runtime `integrity_manifest.json` |
| PyInstaller app | bundled integrity manifest |
| Pip package | package metadata/RECORD or bundled manifest |

The source tree verifier must not use daemon or notifier manifests, and runtime checks must not use source manifests. Legacy mode names `system_runtime`, `user_runtime`, and `pypi_wheel` are accepted and normalized to `system_daemon_runtime`, `user_notifier_runtime`, and `pip_package`.

## Included Files

Stable application files:

- `mac_audit_agent/**/*.py`
- stable package assets/templates
- plist/config/report templates
- launcher/helper/runtime scripts where part of the selected mode
- `pyproject.toml` and requirements files when present

## Excluded Files

Mutable or generated files are excluded:

- `__pycache__/`, `*.pyc`
- `.git/`, `.pytest_cache/`, `.mypy_cache/`
- `build/`, `dist/`, `venv/`, `.venv/`
- `logs/`, `reports/`, `diagnostics/`, `evidence/`, `snapshots/`
- `cache/`, `apple_exposure_cache/`
- `*.sqlite`, `*.sqlite3`, `*.db`, `*.log`
- `settings.json`, user notes, generated exports, packet captures, case files
- generated integrity manifest files

These may have evidence hashes elsewhere, but they are not program source integrity inputs.

## Current Bug / Failure Point

The false unhealthy state was introduced when optional source-tree metadata was treated as stronger than file-hash evidence. A trusted manifest could match all required files, but a development/source checkout without available git metadata, a dirty checkout warning, or stale legacy source state could be interpreted as `unknown`, `partial`, `stale`, or unhealthy.

## Corrections

- Trusted matching file hashes now remain `verified` unless required metadata conflicts.
- Missing optional git metadata does not make a matching trusted manifest stale or broken.
- Dirty source checkout warnings do not increment skipped count or override matching hashes.
- `build_id` is compared only when both manifest and current build ID are available.
- Mutable excluded files do not affect match status.
- `health_impact` is part of verification results and maps `verified` to healthy.
- Draft or missing manifests remain degraded/unknown, not verified.

## Operational Health Consumption

Operational Health reads source integrity status and maps:

- `verified` -> healthy
- `verified_with_warnings` -> healthy
- `unknown`, `draft`, `stale`, `partial`, `failed` -> degraded
- `modified` -> broken

The UI evidence includes mode, trust state, manifest path, app/build/git comparison, and matched/mismatch/missing counts.
