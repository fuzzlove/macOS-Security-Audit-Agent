# Integrity Stale Wrapper Trace

Date: 2026-07-10

The core verifier can return `VALID` while stale wrappers still show historical or release-gate failures. This trace documents every active source of the old failure text or stale integrity state.

| Match/source | File path | Function/class | Calls IntegrityAuthority | Reads stale cache/DB | Reads legacy manifest | Emits old error directly | Maps dirty git to manifest failure | Runtime | Required fix |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UI Integrity Health | `mac_audit_agent/ui/main_window.py` | `_application_integrity_payload` | Through `IntegrityWrapperAdapter` | May display cache only through wrapper | No | No | No | GUI | Use `IntegrityWrapperAdapter`; policy comes from `MSAA_INTEGRITY_POLICY` / `MSAA_RELEASE_POLICY`. |
| Operational Health | `mac_audit_agent/operational_health.py` | `_source_integrity_health` | Through `IntegrityWrapperAdapter` | No trust from cache | No | No | No | GUI/backend | Use adapter, not `source_integrity.py` legacy fallback. |
| Pre-UAT integrity | `mac_audit_agent/quality/release_integrity_auditor.py` | `run_release_integrity_audit` | Yes | Fresh audit | No active trust from legacy paths | No | No | Pre-UAT CLI | Keep Authority as trust source; legacy release check IDs should be aliases only. |
| CLI verify/status | `mac_audit_agent/integrity/__main__.py` | `command_verify`, `command_status` | Through resolver/Authority | Optional display cache only with `--update-current-status` | No | No | No | CLI | Live verifier wins. |
| Release rehash gate | `mac_audit_agent/integrity/__main__.py` | `command_rehash` | Uses live status for context | No | No | No | Fixed to `RELEASE_GATE_DIRTY_SOURCE_TREE` | CLI release gate | Dirty git blocks release but does not imply signature invalid. |
| Runtime diff verifier | `mac_audit_agent/integrity/strict_verifier.py` | `StrictIntegrityVerifier` | No, legacy diff engine | No | Runtime manifest input | No old string after repair | No | Explicit diff tool/runtime | Keep only for guided diff reports; do not drive current UI trust state. |
| Result cache | `mac_audit_agent/integrity/result_cache.py` | JSON cache and `integrity_current_status` | Built from live status | Display-only | No | No | No | GUI/runtime display | Stale cache is labeled stale and never establishes trust. |
| Event reconciliation | `mac_audit_agent/integrity/event_reconciliation.py` | `reconcile_integrity_events_after_verified_repair` | Consumes Authority-derived current status | Active DB events | No | No | No | CLI/dashboard support | Supersede stale active integrity events after live verify passes. |
| Installed runtime drift | `mac_audit_agent/integrity/runtime_sync.py` | `run_runtime_sync_check` | No trust decision | Inspects paths | No | No | No | CLI/runtime diagnostics | Report stale runtime wrapper separately as `INTEGRITY_RUNTIME_STALE`. |
| Consumer comparison | `mac_audit_agent/integrity/consumer_compare.py` | `compare_integrity_consumers` | Yes via Authority and Adapter | Checks cache/active DB | No | No | No | CLI diagnostics | Includes UI, dashboard, Operational Health, Pre-UAT, active DB, runtime wrapper. |
| Public release gate backend | `mac_audit_agent/integrity/consumer_compare.py` | `_public_release_gate_consumer` | Inherits the live Authority baseline | No | No | No | Dirty git maps to `RELEASE_GATE_DIRTY_SOURCE_TREE` in the separate `release_gate` domain | Release diagnostics | Reports release blockers in details without changing integrity status/trust state. |
| UI compatibility model | `mac_audit_agent/integrity/ui_compat.py` | `get_integrity_health_model` | Through `IntegrityWrapperAdapter` | Cache is display-only | No | Only authority-derived failure text | No | GUI backend/tests | Converted from direct Authority use so every displayed backend uses the same adapter contract. |
| Pre-UAT compatibility wrapper | `mac_audit_agent/integrity/pre_uat_compat.py` | `verify_pre_uat_integrity_compatibility` | Through `IntegrityWrapperAdapter` | Cache is display-only | No | No | No | Pre-UAT | Converted from direct Authority use; live adapter status wins. |
| Main-window verification dialog | `mac_audit_agent/ui/main_window.py` | `verify_application_integrity`, `_application_integrity_payload` | Through `IntegrityWrapperAdapter` | No trust from event history | No | Generic failure text only when live result is not `VALID` | No | GUI | Verified results display the authority trust state; historical events are not current truth. |
| Integrity launch gate | `mac_audit_agent/ui/integrity_diff_viewer.py` | `run_launch_integrity_gate`, `_strict_report_from_wrapper` | Through `IntegrityWrapperAdapter` | Writes history only | No | Generic failure text only for a live non-verified adapter result | No | GUI startup | Keep destructive acknowledgement separate; automation must bypass this interactive path. |

## Current Root Cause Fixed

The stale UI/wrapper symptom was consistent with two issues:

- UI and Operational Health were not policy-aware. The CLI could verify `public_release`, while wrappers asked for `dev`.
- `compare-consumers` did not include every displayed consumer, so it could pass while an omitted wrapper still failed.

## Required Display Model

Current integrity trust and release-gate readiness are separate:

- `Integrity: verified` means the signed canonical manifest and files verify.
- `Public release: blocked by dirty source tree` means release signing is blocked by uncommitted changes, with failure code `RELEASE_GATE_DIRTY_SOURCE_TREE`.

Dirty git, failed tests, missing clean install, or stale runtime wrappers must not be displayed as signed-manifest validation failures.

## Installed runtime evidence (2026-07-10)

`runtime-sync-check --policy public_release --json` found both the user and system Application Support runtime packages. Their integrity authority, wrapper adapter, consumer comparison, strict verifier, main window, and service-launch modules differ from the source package. The result is `runtime_in_sync: false`; notifier and daemon plist executables were not readable at the expected canonical labels. Refreshing those packages is an explicit installation operation and was not performed by unit tests.

## Current live-verification qualification

The verified CLI output quoted in the incident report describes an earlier source snapshot. During this repair, the canonical signature still validated, but live strict verification returned `source_files_modified` because the working tree contains extensive changes made after that manifest was signed. This is a genuine current integrity mismatch and must not be hidden by the adapter.

Accordingly:

- adapter parity is fixed and regression-tested;
- a future live `verified` authority result will propagate unchanged to all wrappers;
- the current source checkout must continue to report modified-source integrity until an authorized review-and-sign workflow creates a new canonical manifest;
- dirty Git remains the separate `RELEASE_GATE_DIRTY_SOURCE_TREE` release blocker;
- installed runtime drift remains `INTEGRITY_RUNTIME_STALE` until an authorized reinstall refreshes those copies.
