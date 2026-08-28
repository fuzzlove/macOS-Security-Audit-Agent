# Integrity Manifest Path Audit

Superseded update: the active integrity model now uses one canonical source manifest, `mac_audit_agent/integrity/integrity_manifest.json`, and one canonical signature bundle, `mac_audit_agent/integrity/integrity_manifest.signatures.json`. Legacy development and release manifests below are retained only as discovered migration candidates.

Generated: 2026-07-08

## Confirmed Path Divergence

The previous authorized rehash workflow wrote `mac_audit_agent/security/integrity_manifest.json`, while Pre-UAT release integrity evidence validated `mac_audit_agent/integrity/release_manifest.json` and `mac_audit_agent/integrity/release_manifest.sig`. A clean rehash could therefore report `added=0`, `modified=0`, and `removed=0` against a manifest that Pre-UAT ignored.

## Canonical Registry

All source, release, runtime, CLI, release verification, and Pre-UAT integrity paths now resolve through `mac_audit_agent/integrity/manifest_paths.py`.

| Manifest path | Reader/writer | Command/UI/check | Scope | Status | Migration action |
|---|---|---|---|---|---|
| `mac_audit_agent/integrity/development_manifest.json` | `dev_manifest.rehash_manifest`, `dev_manifest.verify_manifest`, `release_verify.verify_release` in `dev` policy | `python -m mac_audit_agent.integrity rehash --policy dev`; `status --policy dev`; Pre-UAT release integrity in `MSAA_RELEASE_POLICY=dev` | development/source baseline | canonical | Use for manual testing and development integrity. |
| `mac_audit_agent/integrity/development_manifest.sig` | `dev_manifest.rehash_manifest`, `dev_manifest.verify_manifest` | `rehash --policy dev --sign-manifest`; `status --policy dev` | development/source signature | canonical | Optional in dev policy unless caller requires signatures. |
| `mac_audit_agent/integrity/release_manifest.json` | `dev_manifest.rehash_manifest`, `release_sign`, `release_verify.verify_release`, Pre-UAT release integrity | `rehash --policy pre_release`; `rehash --policy public_release`; `release_verify --policy pre_release/public_release` | release source baseline | canonical | Use for signed pre-release and public release validation. |
| `mac_audit_agent/integrity/release_manifest.sig` | `dev_manifest.rehash_manifest`, `release_sign`, `release_verify.verify_release`, Pre-UAT release integrity | `rehash --policy pre_release/public_release --sign-manifest`; `release_verify --policy pre_release/public_release` | release source signature | canonical | Required for pre-release and public release policies. |
| `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.json` | registry path only; runtime install workflows may opt in | runtime policy diagnostics | runtime install baseline | canonical runtime path | Keep outside source tree. |
| `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.sig` | registry path only; runtime install workflows may opt in | runtime policy diagnostics | runtime install signature | canonical runtime path | Keep outside source tree. |
| `mac_audit_agent/security/integrity_manifest.json` | legacy file only | old `rehash --developer-mode` behavior before this fix | legacy development/source baseline | legacy ignored | Do not write. `status --verbose` reports whether it is present. |
| `mac_audit_agent/security/integrity_manifest.json.sig` | legacy file only | old detached signature path before this fix | legacy development/source signature | legacy ignored | Do not write. |
| `msaa_integrity_manifest.json` | older source integrity verifier docs/tests | source integrity legacy baseline | legacy/general source baseline | legacy separate system | Excluded from release manifests; not used by new rehash/Pre-UAT policy resolver. |
| `package_integrity_manifest.json` | package/runtime integrity helpers | package install verification | package integrity | legacy separate system | Excluded from release manifests; not used by new source release policy resolver. |
| `integrity_manifest.json` | runtime app/package helpers | runtime install verification | runtime integrity | runtime/local | Excluded from source release manifests. |
| `dist/MSAA_RELEASE_ARTIFACTS.json` | `release_sign`, `release_verify` | artifact signing and public release verification | distribution artifacts | canonical artifact manifest | Separate from source manifest; validated only when release policy requires artifacts. |
| `dist/MSAA_RELEASE_ARTIFACTS.sig` | `release_sign`, `release_verify` | artifact signing and public release verification | distribution artifact signature | canonical artifact signature | Separate from source manifest; validated only when release policy requires artifacts. |

## Policy Mapping

| Policy | Manifest Pre-UAT validates | Signature Pre-UAT validates | Release artifact checks |
|---|---|---|---|
| `dev` | `mac_audit_agent/integrity/development_manifest.json` | `mac_audit_agent/integrity/development_manifest.sig` when present/requested | `non_applicable_for_policy` |
| `pre_release` | `mac_audit_agent/integrity/release_manifest.json` | `mac_audit_agent/integrity/release_manifest.sig` | required |
| `public_release` | `mac_audit_agent/integrity/release_manifest.json` | `mac_audit_agent/integrity/release_manifest.sig` | required |
| `runtime` | `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.json` | `~/Library/Application Support/MacAuditAgent/runtime/install_manifest.sig` | not source release validation |

## Generated File Scope

Generated or mutable files are excluded through `mac_audit_agent/integrity/exclusions.py`, including:

- `docs/PRE_UAT_*_AUDIT.md`
- `docs/*_AUDIT.md`
- `macos_security_audit_agent.egg-info/`
- `.tmp_pre_uat/`
- `reports/pre_uat/`
- `release_evidence/`
- `build/`
- `dist/`
- `__pycache__/`
- `*.pyc`
- `.pytest_cache/`
- `.ruff_cache/`
- `.mypy_cache/`
- `*.sqlite3`, `*.sqlite3-wal`, `*.sqlite3-shm`
- `.DS_Store`

UI control and button layout audits now write generated reports to `reports/pre_uat/ui_audits/` by default instead of source-controlled `docs/`.

## Pre-UAT Guard

Pre-UAT now emits `integrity.manifest_path_consistency`. It compares the registry-selected rehash path, release verification path, Integrity Health path, and Pre-UAT path for the selected policy. Divergence is a blocker.
