# Integrity Failure Trace

## User-Facing Failure

The recurring message was:

`Signed manifest validation failed. Unsigned or modified manifests cannot establish trust.`

This text was emitted by `mac_audit_agent/quality/release_integrity_auditor.py` in the `integrity.signed_manifest_valid` Pre-UAT check. The message was correct for a genuinely unsigned or modified manifest, but the surrounding implementation previously mixed legacy release-manifest validation with development policy evidence.

## Split-Brain Paths Found

| Consumer | Previous validation path | Risk | Fixed authority path |
| --- | --- | --- | --- |
| CLI strict verify | `integrity.status_resolver.resolve_integrity_status()` | Canonical developer-machine verifier, already correct | `IntegrityAuthority.verify()` / same resolver |
| CLI doctor | `dev_manifest.doctor_status()` | Used older manifest summary fields and did not expose path consistency | `IntegrityAuthority.doctor()` |
| Pre-UAT integrity | `release_integrity_auditor` plus legacy `verify_release()` | Dev policy could carry release-style evidence and old release check names | `IntegrityAuthority.status()` and policy resolver |
| Integrity Health / dashboard | `verify_current_install_integrity()` and `select_integrity_manifest()` | Could select legacy `msaa_integrity_manifest.json` or runtime-style manifests | `IntegrityAuthority.status()` |
| Operational Health source integrity | `source_integrity.verify_source_integrity()` with DB baseline and legacy manifest fallback | Stale DB baseline or legacy source manifest could override signed canonical state | `IntegrityAuthority.status()` |
| Public release gate | Dedicated gate | Release evidence must fail closed on real prerequisites | `IntegrityAuthority` plus artifact gate |

## Canonical Paths

All source integrity consumers now resolve:

- Manifest: `mac_audit_agent/integrity/integrity_manifest.json`
- Signature: `mac_audit_agent/integrity/integrity_manifest.signature.json`
- Developer-machine registry: `mac_audit_agent/integrity/trusted_developer_machines.json`

Legacy paths are discovery-only:

- `mac_audit_agent/security/integrity_manifest.json`
- `mac_audit_agent/integrity/release_manifest.json`
- `mac_audit_agent/integrity/development_manifest.json`
- `mac_audit_agent/integrity/release_manifest.sig`
- `mac_audit_agent/integrity/development_manifest.sig`

## Generated Artifact Handling

Generated artifacts are excluded from source trust decisions through `mac_audit_agent/integrity/exclusions.py`, including Pre-UAT reports, egg-info metadata, caches, build/dist output, runtime DBs, and logs. Generated drift may appear under `modified_generated_files`, but it must not produce source tamper.

## PASS With Failed Evidence

`mac_audit_agent/quality/check_consistency.py` now normalizes checks globally. If a check is marked PASS while top-level evidence says `status=failed` or `status=error`, the check is converted to FAIL/BLOCKER according to its configured severity. Non-applicable policy evidence remains SKIPPED/non-applicable.

## Headless Safety

Integrity authority, doctor, status, verify, repair/sign, Pre-UAT integrity checks, and public release gate remain headless. They must not import PySide6, Qt, AppKit, Cocoa, or create QApplication.
