# Integrity Consumer Audit

Date: 2026-07-09

This audit tracks every active MSAA consumer that can surface integrity state after `repair-and-sign`. The authoritative trust source is `mac_audit_agent.integrity.authority.IntegrityAuthority`; result cache files are display context only and cannot establish trust.

| Consumer | File path | Function/class | Manifest path | Signature path | Evidence freshness | Uses IntegrityAuthority | Policy | Display/failure string | Required fix |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CLI status | `mac_audit_agent/integrity/__main__.py` | `command_status` | `integrity_manifest_paths(...).manifest_for_policy(policy)` | `signature_for_policy(policy)` | Live verification | Indirect through `resolve_integrity_status` | CLI `--policy`, default `dev` | `status`, `trust_state`, `failure_code` | Keep live-first; cache is secondary display only. |
| CLI verify | `mac_audit_agent/integrity/__main__.py` | `command_verify --strict` | canonical policy path | canonical signature bundle | Live verification | Indirect through `resolve_integrity_status` | CLI `--policy` | typed `result_code`/`failure_code` | No direct manifest readers in strict mode. |
| CLI repair-and-sign | `mac_audit_agent/integrity/auto_sign.py` | `auto_sign_integrity` | canonical policy path | canonical signature bundle | Writes fresh evidence and cache after post-sign verify | Uses canonical rehash/sign/resolve path | CLI `--policy` | verified/divergent recommendation | Must run compare-consumers before saying no action required. |
| Integrity Health UI | `mac_audit_agent/ui/main_window.py` | `_application_integrity_payload` | canonical status payload | canonical signature bundle | Live payload; may show cache as display context | Adapter calls integrity status payload | `dev` runtime display | `CRITICAL` warning payload with mismatch details | Must not implement its own verifier. |
| Pre-UAT audit | `mac_audit_agent/quality/release_integrity_auditor.py` | `run_release_integrity_audit` | `IntegrityAuthority.resolve_policy()` | `IntegrityAuthority.resolve_policy()` | Fresh checks during audit run | Yes | `MSAA_RELEASE_POLICY`, default `dev` | exact `result_code: failure_code: reason` | `pre_uat_compatible=true` must mean this function passed. |
| Release readiness | `mac_audit_agent/integrity/public_release_gate.py` | `run_public_release_gate` | source canonical plus artifact manifest in release mode | source canonical plus artifact signature | Fresh release gate run | Uses status/preflight/independent verifier | public release workflow | blocking check list | Dev policy must not report `release_artifact_mismatch`. |
| Operational health | `mac_audit_agent/operational_health.py` | `_source_integrity_health` | Authority canonical path | Authority signature path | Fresh during health report | Yes after this repair | `dev` | Source Integrity card | Legacy `verify_source_integrity` must not be the primary dashboard state. |
| Dashboard health summary | `mac_audit_agent/operational_health.py` | `build_report` | Authority canonical path | Authority signature path | Fresh during report | Yes after this repair | `dev` | report `details["source_integrity"]` | Use Authority dict, not stale source-integrity store. |
| Event alert generator | `mac_audit_agent/integrity/event_reconciliation.py` | `reconcile_integrity_events_after_verified_repair` | current verified status | current verified status | Fresh repair status only | Consumes Authority-derived status/cache | current policy | superseded historical events | Mark old criticals superseded, do not delete or suppress future events. |
| Integrity finding renderer | `mac_audit_agent/ui/main_window.py`, reports | UI/render payloads | Authority payload | Authority payload | Fresh or cache display context | Adapter result | `dev` | `CRITICAL` on concrete failure codes | Must separate active and historical/superseded events. |
| Report exporters | `mac_audit_agent/quality/pre_uat_audit.py`, report output | Pre-UAT report serialization | Pre-UAT Authority path | Pre-UAT Authority path | Fresh audit run | Yes via release integrity auditor | env policy | check IDs under `integrity.*` | No stale evidence can produce PASS. |
| Installed/runtime manifest verifier | `mac_audit_agent/integrity/strict_verifier.py` | `StrictIntegrityVerifier` | runtime manifest path | detached signature state | Live runtime comparison | Legacy verifier; string fixed | runtime/app bundle | `SIGNATURE_INVALID` or typed changes | Keep as runtime diff engine only; do not supersede Authority for CLI/Pre-UAT. |

## Root Cause

The core repair-and-sign path could verify successfully while downstream consumers still reported errors because some consumers were reading legacy or stale state:

- Operational Health used `verify_source_integrity()` as its primary source instead of `IntegrityAuthority`.
- Pre-UAT compatibility was inferred from status flags unless the exact Pre-UAT integrity function was checked.
- Old integrity events could remain active after a successful verified repair.
- Canonical trust metadata files were classified with generated artifacts, making benign trust-file updates look like source drift.
- Legacy manifests such as `development_manifest.json`, `release_manifest.json`, and `mac_audit_agent/security/integrity_manifest.json` were still discoverable and could confuse older readers.

## Required Active Path

All current consumers must use:

```text
IntegrityAuthority.status(policy)
IntegrityAuthority.verify(policy)
IntegrityAuthority.repair_and_sign(policy, options)
```

Direct trust decisions from `release_manifest.json`, `development_manifest.json`, `security/integrity_manifest.json`, cached evidence, or UI-only logic are not acceptable.

## Verification Command

Use this to prove consumer agreement:

```bash
python3.12 -m mac_audit_agent.integrity compare-consumers --policy dev --json
```

`status=pass` means CLI status, CLI verify, Pre-UAT integrity, Integrity Health/backend state, release readiness/backend state, dashboard/backend state, event reconciliation, and display cache freshness agree.
