# Integrity Rehash / Pre-UAT Path Divergence

Superseded update: the active integrity model now uses one canonical source manifest, `mac_audit_agent/integrity/integrity_manifest.json`, and one canonical signature bundle, `mac_audit_agent/integrity/integrity_manifest.signatures.json`. Policy-specific development and release manifest files are legacy/discovery inputs only.

Generated: 2026-07-08

## Confirmed Issue

The legacy rehash command previously accepted `--developer-mode --release-mode` and wrote:

```text
mac_audit_agent/security/integrity_manifest.json
```

Pre-UAT release integrity checks validated:

```text
mac_audit_agent/integrity/release_manifest.json
mac_audit_agent/integrity/release_manifest.sig
```

That meant rehash could print `added: 0`, `modified: 0`, and `removed: 0` for a manifest Pre-UAT did not use.

## Canonical Path Resolver

Canonical path selection lives in:

```text
mac_audit_agent/integrity/manifest_paths.py
```

All new rehash, release verification, Pre-UAT release integrity, and Integrity Health source fallback logic resolve policy paths through that module.

## Path Inventory

| Path | Reader | Writer | Command | UI | Pre-UAT check | Release verifier | Policy | Status | Migration action |
|---|---|---|---|---|---|---|---|---|---|
| `mac_audit_agent/integrity/development_manifest.json` | `dev_manifest.verify_manifest`, `release_verify.verify_release`, `source_integrity.verify_source_integrity` fallback | `dev_manifest.rehash_manifest` | `integrity rehash --policy dev`; `integrity verify --policy dev`; `integrity release_verify --policy dev` | Integrity Health via source integrity fallback | `integrity.release_files_match_manifest` is `non_applicable_for_policy`; dev source validation uses this path | `verify_release(..., mode="dev")` | `dev` | canonical | Use for development/manual testing baseline. |
| `mac_audit_agent/integrity/development_manifest.sig` | `dev_manifest.verify_manifest`, `status --verbose` | `dev_manifest.rehash_manifest --sign-manifest` | `integrity rehash --policy dev --sign-manifest` | Integrity Health evidence when present | dev policy signature evidence | dev release verifier evidence | `dev` | canonical | Optional unless signing is requested. |
| `mac_audit_agent/integrity/release_manifest.json` | `release_verify.verify_release`, Pre-UAT release integrity | `dev_manifest.rehash_manifest`, `release_sign` | `integrity rehash --policy pre_release/public_release`; `integrity release_verify --policy pre_release/public_release` | not directly loaded by UI | `integrity.release_manifest_exists`, `integrity.release_files_match_manifest` | release verifier source manifest | `pre_release`, `public_release` | canonical | Use for signed source release baseline. |
| `mac_audit_agent/integrity/release_manifest.sig` | `release_verify.verify_release`, Pre-UAT release integrity | `dev_manifest.rehash_manifest --sign-manifest`, `release_sign` | `integrity rehash --policy pre_release/public_release --sign-manifest` | not directly loaded by UI | `integrity.release_manifest_signature_valid` | release verifier signature | `pre_release`, `public_release` | canonical | Required in release policies. |
| `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.json` | runtime policy resolver | runtime install workflows | `integrity status --policy runtime` | runtime integrity views may surface it | not source Pre-UAT | not source release verifier | `runtime` | canonical runtime | Keep outside source tree. |
| `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.sig` | runtime policy resolver | runtime install workflows | `integrity status --policy runtime` | runtime integrity views may surface it | not source Pre-UAT | not source release verifier | `runtime` | canonical runtime | Keep outside source tree. |
| `mac_audit_agent/security/integrity_manifest.json` | legacy status detection only | only with explicit `--legacy-output --manifest ...` | old `integrity rehash --developer-mode`; rejected when paired with `--release-mode` | none | not validated | not validated | legacy | ignored | Do not use for Pre-UAT. Migrate to canonical dev/release manifest. |
| `mac_audit_agent/security/integrity_manifest.json.sig` | legacy status detection only | only with explicit legacy output | old detached signature path | none | not validated | not validated | legacy | ignored | Do not use for Pre-UAT. |
| `msaa_integrity_manifest.json` | older source integrity verifier and tests | older manifest tooling | older `integrity.manifest` workflows | legacy integrity UI/test paths | not release Pre-UAT policy resolver | not release verifier | legacy source | separate legacy system | Kept as fallback/documented legacy path. |
| `package_integrity_manifest.json` | package integrity verifier | package manifest tooling | package verification workflows | package integrity evidence | not source release Pre-UAT | not release verifier | package | separate legacy/runtime system | Excluded from source release manifest scope. |
| `integrity_manifest.json` | runtime/package helpers | runtime/package manifest tooling | runtime/package verification workflows | runtime integrity evidence | not source release Pre-UAT | not release verifier | runtime/package | separate runtime path | Excluded from source release manifest scope. |

## CLI Policy Rules

- `--developer-mode` alone maps to `--policy dev`.
- `--release-mode` alone maps to `--policy public_release`.
- `--developer-mode --release-mode` is rejected.
- `--policy dev`, `--policy pre_release`, `--policy public_release`, and `--policy runtime` are canonical.
- Legacy output requires `--legacy-output` and an explicit legacy `--manifest` path.

## Generated Artifact Scope

Generated files that previously caused release manifest mismatch are out of scope:

- `docs/PRE_UAT_*_AUDIT.md`
- `docs/*_AUDIT.md`
- `macos_security_audit_agent.egg-info/`
- `.tmp_pre_uat/`
- `reports/pre_uat/`
- `*.sqlite3`, `*.sqlite3-wal`, `*.sqlite3-shm`

Pre-UAT UI audit reports now default to:

```text
reports/pre_uat/ui_audits/
```

## Guardrail

Pre-UAT check `integrity.manifest_path_consistency` compares the rehash path resolver, release verifier path resolver, Pre-UAT path resolver, and Integrity Health path resolver for the selected policy. Divergence is a blocker.
