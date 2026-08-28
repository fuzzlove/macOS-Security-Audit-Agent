# Threat Definition Update & Blocklist Intelligence Engine

## Security objective

MSAA treats threat intelligence as versioned defensive evidence, not as an unreviewed text blocklist. The subsystem preserves provenance, validates formats and policy, stages immutable bundles, verifies detached Ed25519 signatures and per-file SHA-256 hashes, activates one complete version atomically, and retains the previous known-good version.

Desktop installations include the `cryptography` and `yara-python` definition dependencies. For a modular source checkout, install them with `python3 -m pip install -e ".[definitions]"`; no manual YARA compilation or rule copying is required.

An Internet or provider failure never deletes the active definitions. A stale bundle remains usable and is reported as stale. A feed entry does not automatically authorize blocking.

## Architecture

```text
provider adapter / signed offline bundle
                 |
                 v
 bounded download and staging
                 |
                 v
 normalization -> provenance -> deduplication -> lifecycle
                 |
                 v
 schema / delta / YARA compile / benign fixture / performance gates
                 |
                 v
 release manifest + per-file SHA-256 integrity
 optional/enforced detached Ed25519 signature
                 |
                 v
 immutable version + atomic active pointer
                 |
                 v
 sensor reload validation -> stabilization or rollback
```

Primary modules are under `mac_audit_agent/threat_definitions/`:

- `models.py`: definition types, actions, lifecycle, provenance, source policy, behavior rule model, validation and health models.
- `normalization.py`: strict IDNA, URL, IP, CIDR, and hash canonicalization. It never turns a host into a wildcard parent-domain block.
- `sources.py`: isolated adapters and provider policy metadata.
- `validation.py`: format, provenance, confidence, delta, behavior-schema, YARA compilation, benign-fixture, and performance gates.
- `lifecycle.py`: type-specific expiration. Shared infrastructure indicators expire sooner than immutable file hashes.
- `store.py`: immutable bundles, hash manifests, detached signatures, quarantine, offline import, atomic activation, and rollback.
- `intelligence.py`: normalized SQLite hash/provenance indexes, source health, and the metadata-keyed file-hash cache.
- `sensor_reload.py`: load validation, reload requests, sensor receipts, and release-desynchronization detection.
- `locking.py`: process-safe single-updater locking.
- `policy.py`: update, jitter, retention, import batching, and staleness policy.
- `matcher.py`: typed lookups with allowlist conflict disclosure. Allowlisting can suppress prevention but cannot suppress detection.
- `manager.py`: update orchestration, source isolation, deduplication, status, activation, and rollback.
- `scheduler.py`: provider-aware intervals, jitter, and isolated scheduled updates.
- `diagnostics.py`: sanitized HTML, DOCX, XLSX, and JSON health reports.

## Definition and action policy

Supported definition classes include YARA, MD5/SHA-1/SHA-256, domains, hostnames, URLs, IPv4/IPv6/CIDR, certificate hashes and identities, malware families, generic IOCs, behavior/detection rules, allowlists, and denylists.

Actions are `OBSERVE`, `LOG`, `ALERT`, `CORRELATE`, `QUARANTINE_CANDIDATE`, `BLOCK`, and `DISABLED`. External feed `BLOCK` requests are reduced to `ALERT` until an explicit prevention policy approves them. URL reputation, domain reputation, and IP reputation remain separate; a malicious URL never automatically creates a permanent destination-IP block.

Deduplication stores one canonical indicator with multiple source relationships. Effective confidence counts independent dependency groups, so mirrored downstream feeds do not masquerade as independent corroboration.

## Provider policy

The public CISA KEV correlation source is enabled by default; it does not provide malware file hashes or YARA rules. All executable-definition and malware-IOC providers require explicit administrator source/licensing approval. Current abuse.ch community exports require an Auth-Key, and commercial/for-profit use may require an appropriate service agreement. Credentials are supplied outside bundles and are excluded from diagnostics and release metadata.

The desktop console provides **Malware Definitions → Provider Authentication** for the abuse.ch Community API. A saved Auth-Key is stored as a generic password in the current user's macOS Keychain under service `com.liquidsky.msaa.threat-definitions`; MSAA shows only whether it is configured. The key is not stored in application settings, definition releases, update logs, diagnostics, or process arguments. When an update is launched with `sudo`, the credential loader targets the invoking user's login Keychain through the validated `SUDO_UID` account record. `MSAA_ABUSE_CH_AUTH_KEY` remains an ephemeral, process-scoped override for automation and takes precedence over Keychain.

Local, review-only rule learning is documented in
[LOCAL_YARA_LEARNING.md](LOCAL_YARA_LEARNING.md). Learned rules and corpus hashes
never enter an active release automatically; provider trust and release
activation remain separate from local statistical candidates.

Background launchd updates have no interactive login-Keychain context. Select **Enable Automatic Feed Updates** to open the fixed administrator command, then enter the Auth-Key at Terminal's hidden prompt. MSAA provisions a separate generic-password entry in `/Library/Keychains/System.keychain`; the key is passed to `security` over standard input and never appears in the command, clipboard, process arguments, status cache, or logs. The root updater can read this fixed-purpose entry, while the unprivileged GUI receives only a configured/not-configured health result. Public CISA KEV and YARA Forge scheduling remains available without this credential.

The desktop **Refresh Status** action consumes the root-published, sanitized health snapshot. **Verify Active Release** deliberately opens an administrator Terminal command because active manifests and release files are root-restricted. A desktop status-collection error is reported as unavailable and does not relabel a known-good active release as failed.

Desktop administrator handoffs select an executable project virtual environment and change into the repository before invoking `mac_audit_agent.cli`. They do not assume that a global `/usr/local/bin/python3` contains MSAA merely because it launched or can see the source tree. The copied command is absolute, shell-quoted, and uses the same interpreter selection for update, verification, credential provisioning, and updater repair.

Administrator-reviewed generic sources are configured in `/Library/Application Support/MSAA/config/definition_sources.json`, through `MSAA_DEFINITION_SOURCES_CONFIG`, or with `--source-config`. Supported types are `yara`, `sha256`, `sha1`, `md5`, `mixed_hash`, `json_intelligence`, and `csv_intelligence`. Optional `auth_header` plus `auth_env` fields load credentials from a restricted environment at request time; secrets never enter the registry, release, status cache, or logs. The repository template in `config/definition_sources.json` is intentionally disabled and contains no credentials.

Production connected endpoints should normally enable the `msaa_signed_bundle` adapter. Release engineering ingests raw providers, performs normalization and validation, signs the complete bundle outside endpoints, and publishes that immutable artifact. Endpoints download the signed artifact and verify it with pinned public keys; the distribution private key is never installed on clients.

YARA Forge defaults to its Core tier because that tier is intended to prioritize accuracy and endpoint performance. Extended and Full require an explicit selection and still pass MSAA's local compilation, resource, and benign-fixture gates. The constituent rule licenses must be reviewed; a package download cannot grant itself redistribution approval.

MalwareBazaar integration consumes metadata and hashes only. MSAA endpoints do not acquire malware samples.

## Bundle layout

```text
definitions/
    active/current.json
    staging/<version>/
    previous/current.json
    quarantine/
    metadata/
    releases/<immutable-release>/
        manifest.json
        yara/macos/<namespace>/*.yar
        hashes/{sha256,sha1,md5}.txt
        databases/threat_intelligence.sqlite3
        metadata/sources.json
    custom/
    cache/
    manifests/
    logs/
    trusted_keys/<key-id>.pem
```

A release contains `manifest.json` and manifest-listed payload files. Signed releases also contain `manifest.sig` (and the compatibility signature filename). Trusted public keys are administrator-provisioned outside downloaded content. A bundle cannot introduce and immediately trust its own signing key. Signature enforcement is controlled consistently for both updater and sensors by `MSAA_REQUIRE_SIGNED_DEFINITIONS=1`; signed offline imports always require verification.

Offline archives use one top-level version directory and pass the same signature, manifest, hash, schema, path traversal, symlink, size, YARA, compatibility, and activation checks as online content.

## Operational commands

Status and source policy are read-only:

```bash
msaa definitions status --json
msaa definitions sources --json
```

Run the rate-aware scheduled/startup check (only explicitly enabled sources are contacted):

```bash
sudo msaa definitions scheduled-update --activate --json
sudo msaa definitions startup-update --activate --json
sudo msaa definitions update --activate --source-config "/Library/Application Support/MSAA/config/definition_sources.json" --json
sudo msaa definitions update --dry-run --source-config "/Library/Application Support/MSAA/config/definition_sources.json" --json
sudo msaa definitions verify --json
```

Import, validate, and activate an offline bundle:

Replace `/absolute/path/to/...` with a real file produced by the MSAA release pipeline. The example path is not created automatically.

```bash
sudo msaa definitions import "/absolute/path/to/msaa-definitions-2026.08.25.1.bundle" --json
sudo msaa definitions validate "2026.08.25.1" --json
sudo msaa definitions activate "2026.08.25.1" --json
```

Roll back to the retained known-good version:

```bash
sudo msaa definitions rollback --json
```

Export operator diagnostics:

```bash
msaa definitions diagnostics --output "$HOME/Desktop/msaa-definition-health.html" --json
msaa definitions diagnostics --output "$HOME/Desktop/msaa-definition-health.docx" --json
msaa definitions diagnostics --output "$HOME/Desktop/msaa-definition-health.xlsx" --json
```

Release engineering may sign a locally built bundle only with a separately protected Ed25519 key whose file permissions exclude group and other access. Distribution signing keys must not ship in MSAA or definition bundles.

## Health behavior

Sensor Health receives a separate `malware_definitions` provider. It reports active release, freshness, signature/hash validity, hash/YARA counts, source status, reload receipts, and definition-backed coverage. Internet-dependent enrichment can degrade while local sensors remain operational. A missing or invalid release never causes MSAA to claim definition-backed protection.

Top-level health states are `HEALTHY`, `UPDATING`, `STALE`, `DEGRADED`, `FAILED`, `ROLLBACK_ACTIVE`, and `NEVER_UPDATED`. Stale intelligence is not erased or silently disabled. Warning, degraded, and critical age defaults are 24 hours, 72 hours, and 7 days.

The system daemon runs the same production scheduler used by the CLI and GUI. It checks due sources without downloading sources that are not due, uses bounded jitter, and surfaces `DEFINITION_SENSOR_DESYNC` when a sensor receipt reports a release other than the active release.

## Failure handling

- HTTP success with an empty or unexpectedly reduced feed is rejected.
- Provider failures are isolated; one source cannot abort another source's check.
- A malformed IOC is rejected before storage.
- A broken or excessive YARA package cannot replace active rules.
- Unmanifested files, hash mismatches, invalid signatures, symlinks, and archive traversal are rejected.
- Failed sensor reload restores the previous active pointer.
- Rejected offline imports are quarantined; active definitions remain untouched.
- Update history records staging, activation, rejection, rollback, and recovery evidence without credentials.

## Adding a source

A new source must implement the `ThreatSourceAdapter` contract, provide a `SourcePolicy`, preserve original and normalized values, describe dependency grouping, and document licensing. It must have parser fixtures, malformed-input tests, delta expectations, lifecycle policy, and source-isolation tests before it is enabled.

Standards and public feeds are engineering references only. MSAA does not claim endorsement or certification by CISA, NIST, abuse.ch, YARA Forge, or any other provider.
