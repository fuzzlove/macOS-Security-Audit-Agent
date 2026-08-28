# MSAA Integrity Rehash and Verification

MSAA uses one canonical source integrity manifest:

```bash
mac_audit_agent/integrity/integrity_manifest.json
```

The canonical detached signature bundle is:

```bash
mac_audit_agent/integrity/integrity_manifest.signature.json
```

Trusted developer-machine public identities are stored in:

```bash
mac_audit_agent/integrity/trusted_developer_machines.json
```

Legacy manifests such as `mac_audit_agent/security/integrity_manifest.json`, `development_manifest.json`, and `release_manifest.json` may be discovered for diagnostics, but they do not override the canonical manifest.

The manifest is split into signed and unsigned sections:

- `payload`: trusted content covered by the detached signature.
- `metadata`: display/build/runtime context that is not trusted for integrity decisions.
- `integrity_manifest.signature.json`: detached signature bundle over canonicalized `payload`.

The signed `payload` is deterministic canonical JSON:

- sorted keys
- compact separators
- UTF-8
- project-relative POSIX paths
- stable path ordering
- no embedded private key material
- no top-level shadow copies of trusted fields
- no `signature`, `signature_algorithm`, `public_key`, or `signed_at` fields in the signed payload
- no manifest self-hash or signature-file hash
- no file `last_modified` timestamps

The signature bundle is detached from the manifest and records the manifest SHA-256, signing model, public key fingerprint, build metadata, and base64 signature.

## Default Workflow

Enroll the developer Mac:

```bash
python3.12 -m mac_audit_agent.integrity machine enroll \
  --developer "Liquidsky Network Security" \
  --organization "Liquidsky Network Security" \
  --machine-label "Liquidsky Primary Dev Mac" \
  --use-secure-enclave
```

Sign the current development baseline:

```bash
export BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"

python3.12 -m mac_audit_agent.integrity sign \
  --policy dev \
  --developer-machine \
  --author "Liquidsky Network Security" \
  --reason "approved development baseline" \
  --build-id "$BUILD_ID"
```

Verify:

```bash
python3.12 -m mac_audit_agent.integrity verify --policy dev --strict
python3.12 -m mac_audit_agent.integrity status --policy dev --verbose
```

## Release Signing Workflow

The release private key must remain outside the repository. The pinned public verification key must be bundled at:

```bash
mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem
```

Generate and sign the release manifest:

```bash
BUILD_ID="$(git rev-parse --short HEAD)"
RELEASE_ID="msaa-$(date -u +%Y%m%d)-$BUILD_ID"

python3.12 -m mac_audit_agent.integrity rehash \
  --release-mode \
  --require-clean-git \
  --sign-manifest \
  --private-key "$MSAA_INTEGRITY_PRIVATE_KEY_PATH" \
  --author "Liquidsky Network Security" \
  --reason "release build" \
  --build-id "$BUILD_ID" \
  --release-id "$RELEASE_ID"
```

Verify the signed manifest:

```bash
python3.12 -m mac_audit_agent.integrity verify --policy public_release --strict
python3.12 -m mac_audit_agent.integrity doctor --policy public_release --json
```

Release signing writes `integrity_manifest.signature.json` as a JSON signature bundle with `signature_model=trusted_release_key` and `signed_payload=canonical_manifest_json_bytes`. Verification uses the same canonical verifier as CLI status, Integrity Health, Pre-UAT, and release readiness. Normal app runtime never auto-rehashes or auto-trusts modified files.

`doctor` audits and prints the manifest path, manifest existence, public key source and fingerprint, private-key requirement for verification (`false`), signature presence and validity, hash algorithm, tracked and excluded file counts, release ID, build ID, git commit, current result code, exact failure reason, and remediation steps.

## Result Codes

Runtime and CLI verification return a typed result code:

- `VALID`
- `MANIFEST_MISSING`
- `MANIFEST_UNSIGNED`
- `SIGNATURE_INVALID`
- `PUBLIC_KEY_MISSING`
- `HASH_MISMATCH`
- `FILE_MISSING`
- `UNEXPECTED_FILE`
- `UNSUPPORTED_BUNDLE_LAYOUT`
- `INTERNAL_ERROR`

The application must not show `unknown` or `unverifiable` as the signed-release integrity result. Any exception is caught by the resolver and mapped to `INTERNAL_ERROR` with the exception class and a safe message.

## Root Cause Audit

The prior failure mode came from multiple integrity paths reporting vague fallback states. The strict/runtime path initialized failed manifest loads and invalid signatures as `unknown`, while the GUI had its own status adapter and only treated developer-machine trust as valid. A valid release-key signed manifest could therefore verify at the CLI but still appear failed or ambiguous in the app. Some output also omitted the release metadata and public key fingerprint needed to prove which signed release was being checked.

The fixed path uses one authoritative signed-manifest validator for CLI, Doctor, GUI integrity health, Pre-UAT, and release readiness. The validator canonicalizes only the signed `payload`, verifies the detached signature with the pinned public key, compares current file hashes to the signed tracked file list, and emits the specific result code. GUI code is now only an adapter over that result.

## Protected Scope

Protected files include Python source, GUI and monitor entry points, notifier code, scanner modules, rule and severity data, launchd plist templates, bundled scripts, export templates, and security policy metadata.

Generated files are excluded, including logs, SQLite databases, caches, reports, Pre-UAT generated audit outputs, `*.egg-info`, temporary files, `__pycache__`, virtual environments, build outputs, and `.git`.

## Trust Model

Developer-machine signing binds manifest approval to an enrolled Mac and local signing key. The public key and salted machine fingerprints are stored in `trusted_developer_machines.json`; raw serial numbers and raw UUID values are not stored.

Any machine can verify a signed manifest using the trusted public key. Signing is refused unless the current machine fingerprint matches an active enrolled developer machine.

Developer-machine signing is not equivalent to YubiKey hardware-token signing and cannot fully protect against a compromised enrolled developer machine.

Release-key signing uses the pinned Ed25519 public key bundled in source/app resources. Verification fails closed if the pinned public key is missing, if the public key fingerprint differs from the signature bundle, or if the canonical manifest bytes no longer match the signed hash.

## Troubleshooting

### Dirty Git Tree

Release signing with `--require-clean-git` refuses modified, staged, or untracked files and prints each blocking path. Commit, stash, or remove unintended changes before public release signing. Do not use a dirty tree for public release signing.

### Wrong Private Key

If the private key does not match the pinned public key, signing may complete but post-sign verification fails with `signature_invalid` or a public key fingerprint mismatch. Use the private key corresponding to `mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem`.

### Missing Public Key

Verification fails closed with `trusted_public_key_missing` if the pinned public key is absent. Restore the public key from the trusted source tree or release resources. Do not trust a public key embedded only in a modified manifest.

### Path Mismatch

Doctor output shows the canonical manifest path and signature path. Dev and public release policies both use `mac_audit_agent/integrity/integrity_manifest.json` for source integrity. Legacy paths such as `release_manifest.json` are discovery-only and must not be signed as the active trust source.

### Stale Manifest

If a source file changed after manifest generation, verification reports `source_files_modified` and lists modified, missing, or unexpected files. Review the change, then regenerate and sign only through the authorized workflow.

### Modified Manifest

If `integrity_manifest.json` is edited after signing, verification reports `manifest_modified_after_signing`. Trusted fields such as `reason`, `build_id`, `release_id`, and `files` must live under `payload`; top-level shadow copies are treated as manifest tampering. Regenerate the manifest and signature from a trusted clean source tree.

### App Bundle Validation Failure

Packaged app validation must resolve resources relative to the app bundle, never absolute developer-machine paths. If bundle validation fails, check that the manifest, signature bundle, and pinned public key are packaged together and that all manifest paths are project/app-resource-relative POSIX paths.

## Control Alignment

The implementation uses FIPS 180-4 SHA-256 file hashing. Public release manifests use Ed25519 release-key signatures. Developer-machine manifests use the enrolled developer-machine signing backend. It provides CISA Secure by Design, NIST SSDF, CMMC, and DoD readiness/evidence support for configuration management, system integrity, auditability, and incident response. It does not claim CISA approval, DoD approval, CMMC certification, NIST compliance, or government approval.
