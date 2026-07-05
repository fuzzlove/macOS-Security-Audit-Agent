# Source Hash Operational Health Audit

## Summary

Operational Health uses `mac_audit_agent.source_integrity.verify_source_integrity()` for Python source integrity status. That path previously did not distinguish missing, draft, stale, partial, failed, and modified states clearly enough for production health reporting. The fix keeps integrity enforcement intact while preventing normal development or untrusted draft hash data from being reported as a generic broken Operational Health state.

## Current Hashing Paths

| Area | Code | Source of Truth | Storage |
|---|---|---|---|
| Legacy source health | `mac_audit_agent/source_integrity.py` | Stored trusted source manifest payload | `background_monitor_state:source_integrity_manifest_v1` |
| Manifest generation | `mac_audit_agent/integrity/manifest.py` | Explicit trusted or draft manifest | `msaa_integrity_manifest.json` or selected output |
| Manifest verification | `mac_audit_agent/integrity/verifier.py` | Existing manifest only | Caller-provided manifest path |
| Operational Health | `mac_audit_agent/operational_health.py` | Source integrity payload status | Operational Health table/details |
| UI actions | `mac_audit_agent/ui/operational_health_panel.py` and `main_window.py` | User-triggered verification/manifest creation | Application support/source tree |

## Hash Scope

Stable application files are included:

- `mac_audit_agent/**/*.py`
- packaged assets/templates
- `pyproject.toml`
- requirements/config/template files
- helper/runtime scripts and plist templates

Mutable or generated operational data is excluded by `DEFAULT_EXCLUDED_PATTERNS`:

- `__pycache__/`, `*.pyc`
- `.git/`, `.pytest_cache/`, `.mypy_cache/`
- `venv/`, `.venv/`, `build/`, `dist/`
- `logs/`, `reports/`, `diagnostics/`, `evidence/`, `snapshots/`
- `*.sqlite`, `*.sqlite3`, `*.db`, `*.log`
- `settings.json`, `cache/`, `apple_exposure_cache/`
- user exports, packet captures, investigation notes, case files
- generated integrity manifest files

These files may be hashed as evidence elsewhere, but they are not Python source integrity inputs.

## Manifest Trust States

`IntegrityManifest.trust_state` is now explicit:

- `trusted`: may verify files and can produce `verified` or `modified`
- `draft`: preview only; cannot produce verified
- `expired`: translated to stale verification state
- `revoked`: untrusted; cannot produce verified
- `unknown`: untrusted; cannot produce verified

Legacy manifests without `trust_state` load as `trusted` and keep legacy manifest hash compatibility.

## Operational Health Interpretation

| Integrity status | Operational Health status | Meaning |
|---|---|---|
| `verified` | `healthy` | Trusted manifest exists and files match |
| `unknown` | `degraded` | No trusted manifest or trust source unavailable |
| `draft` | `degraded` | Draft hash data exists but is not trusted |
| `stale` | `degraded` | Manifest version/build/commit no longer matches current app |
| `partial` | `degraded` | Optional/unreadable checks prevented full verification |
| `failed` | `degraded` | Verifier failed and reports exact error |
| `modified` | `broken` | Trusted source/runtime files differ from manifest |

Operational Health must not show a generic broken status for missing manifests, draft manifests, dirty development checkouts, logs/databases/settings changes, or stale trusted manifests after an intentional update.

## Draft Workflow

Draft manifests can be created with `--draft`. They are useful for previewing included files and diagnostics, but they are not trusted.

Rules:

- draft manifests cannot verify source integrity
- draft manifests do not trigger tamper alerts
- draft manifests do not break Operational Health
- promotion to trusted still requires explicit trusted confirmation

## Trusted Workflow

Trusted manifest creation still requires:

- user confirmation in the UI
- typed confirmation: `TRUST CURRENT FILES`
- old manifest backup when replaced

The app does not silently recalculate trusted hashes after detecting drift.

## Why Operational Health Was Misleading

The source integrity health check previously treated all non-tamper states as healthy and exceptions as broken. That collapsed important production states:

- missing trusted manifest
- draft manifest
- stale version/build
- source checkout without trust source
- verifier failure

The fix returns exact integrity state and evidence so Operational Health can show a precise degraded/warning state unless a trusted manifest mismatch is actually detected.

## Fixed Behavior

- missing manifest: `unknown`, degraded, recommended action to create trusted manifest after trusted install
- draft manifest: `draft`, degraded, explicit message that draft cannot prove integrity
- stale manifest: `stale`, degraded, explicit app/build mismatch message
- trusted matching manifest: `verified`, healthy
- trusted mismatch: `modified`, broken, preserve evidence/reinstall guidance
- verifier exception: degraded with exact error, not a generic broken source hash message
