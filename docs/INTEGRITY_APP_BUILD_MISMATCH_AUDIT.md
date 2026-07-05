# Integrity App Build Mismatch Audit

MSAA now distinguishes stale trusted manifests, incompatible manifest modes, build identity drift, cached-result risk, and actual file modification. The verifier does not trust current files and does not regenerate manifests automatically.

## State Flow

`manifest file -> manifest parser -> BuildIdentity -> source_type compatibility -> metadata comparison -> required file hash verification -> IntegrityVerificationResult -> Operational Health -> reports`

## Diagnostic Fields

| Diagnostic | Source | Purpose |
| --- | --- | --- |
| Selected manifest path | `IntegrityVerificationResult.manifest_path` | Shows the exact manifest being evaluated. |
| Selected manifest source_type | `IntegrityVerificationResult.source_type` | Prevents source/package/runtime mode confusion. |
| Selected manifest trust_state | `IntegrityVerificationResult.trust_state` | Draft/unknown manifests cannot verify integrity. |
| Manifest app_version | `manifest_app_version` | Compared against BuildIdentity app version. |
| Current app_version | `current_app_version` | Derived from `mac_audit_agent.build_identity`. |
| Manifest build_id | `manifest_build_id` | Stable build identifier recorded at manifest generation. |
| Current build_id | `current_build_id` | Stable build identifier for current source/package/app. |
| Manifest git_commit | `manifest_git_commit` | Source tree manifests can pin git commit. |
| Current git_commit | `current_git_commit` | Source tree commit from BuildIdentity/git. |
| Manifest package_version | `manifest_package_version` | Empty for legacy manifests; present as an explicit diagnostic field. |
| Current package_version | `current_package_version` | Derived from installed package metadata when available. |
| Manifest root_path | `manifest_root_path` | Root used when manifest was created. |
| Current runtime/source root | `current_root_path` | Root used for verification. |
| Manifest created_at | Manifest payload | Available in the selected manifest. |
| Manifest hash | `manifest_hash` | Detects corrupt or altered manifests. |
| Current detected install mode | `current_install_mode` | Derived from BuildIdentity or explicit verifier expectation. |
| File hash match count | `matched_count` | Required files that matched. |
| File mismatch count | `mismatched_count` | Required files that changed. |
| Missing required file count | `missing_count` | Required files not present. |
| Extra executable count | `extra_count` | Unexpected executable files. |
| Ignored manifests | `ignored_manifests[]` | Existing manifests skipped because they do not match the active install mode or are lower-priority duplicates. |
| Cached result | `cached_result` | Indicates whether the UI/report is showing a cached verification result. |
| Cache valid | `cache_valid` | False when the cache was bypassed or invalidated by manifest/build/root changes. |
| Cache invalidated reason | `cache_invalidated_reason` | Explains why cached verification could not be reused. |
| Verification result ID | `verification_result_id` | Stable identifier for this verification result payload. |
| Verified at | `verified_at` | Timestamp for the verification result payload. |
| Final status decision | `overall_status` | `verified`, `stale`, `incompatible_manifest`, `modified`, etc. |
| Where mismatch is introduced | `mismatch_details[]` and `exact_mismatch_reason` | Field-level explanation used by UI/reports. |

## Decision Rules

| Condition | Status | Health Impact | Message |
| --- | --- | --- | --- |
| Trusted manifest, matching metadata, required files match | `verified` | healthy | Current build matches trusted manifest. |
| App version/build/git differs, required files match | `stale` | degraded | Manifest was generated for a different MSAA build; this does not by itself prove tampering. |
| Expected source type differs from manifest source type | `incompatible_manifest` | degraded | Selected manifest does not apply to this install mode. |
| Required file hash differs | `modified` | broken | Current files differ from the trusted manifest. |
| Required file missing | `modified` | broken | Required trusted file is missing. |
| No trusted manifest | `unknown` | degraded | No trusted integrity manifest exists. |
| Draft manifest | `draft` | degraded | Draft manifests cannot verify trust. |

## Current Fix Applied

- `mac_audit_agent.build_identity` centralizes app version, package version, git commit, build id, install mode, and roots.
- `mac_audit_agent.integrity.manifest.create_integrity_manifest()` records stable build identity; it does not use timestamps or random UUIDs as build ids.
- `mac_audit_agent.integrity.verifier.verify_integrity_manifest()` records exact metadata mismatch fields, continues file hashing after metadata mismatch, and returns `stale` only when required files still match.
- `mac_audit_agent.integrity.verifier.select_integrity_manifest()` selects the manifest for the active `BuildIdentity.install_mode` and reports wrong-mode manifests as ignored diagnostics instead of silently using them.
- `verify_current_install_integrity(..., bypass_cache=True)` is used by the UI Verify Now flow so stale cached results are not reused.
- Runtime/package/source wrappers pass the expected source type so wrong manifests are classified as `incompatible_manifest`.
- Operational Health includes manifest/current app, build, git, source type, and exact mismatch reason.
- HTML reports include manifest/current version/build and explain stale manifests without calling them tampering.

## Safe Repair Guidance

If status is `stale` and required file hashes match, use the trusted update workflow: verify the update source, back up the old manifest, then create a new trusted manifest only after explicit confirmation.

If status is `modified`, preserve evidence and reinstall from a trusted source unless the file changes are known and approved.

If status is `incompatible_manifest`, select or generate a trusted manifest for the current install mode.
