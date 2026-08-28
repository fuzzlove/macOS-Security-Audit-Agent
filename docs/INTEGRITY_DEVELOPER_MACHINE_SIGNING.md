# Developer-Machine Integrity Signing

MSAA integrity signing uses one canonical source manifest and one developer-machine signature bundle:

- `mac_audit_agent/integrity/integrity_manifest.json`
- `mac_audit_agent/integrity/integrity_manifest.signature.json`
- `mac_audit_agent/integrity/trusted_developer_machines.json`

YubiKey signing is optional legacy/experimental support. It is not required for integrity verification, Pre-UAT, or release readiness.

## Enroll This Developer Mac

```bash
python3.12 -m mac_audit_agent.integrity machine enroll \
  --developer "Liquidsky Network Security" \
  --organization "Liquidsky Network Security" \
  --machine-label "Liquidsky Primary Dev Mac" \
  --use-secure-enclave
```

The current implementation is headless-safe and keeps private key material outside the repository. Raw serial numbers and raw UUID values are not stored; the registry stores salted SHA-256 hashes and public key metadata.

## Sign A Development Baseline

```bash
export BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"

python3.12 -m mac_audit_agent.integrity sign \
  --policy dev \
  --developer-machine \
  --author "Liquidsky Network Security" \
  --reason "approved development baseline" \
  --build-id "$BUILD_ID"
```

## Verify

```bash
python3.12 -m mac_audit_agent.integrity verify --policy dev --strict
python3.12 -m mac_audit_agent.integrity status --policy dev --verbose
```

Expected trusted state:

```text
trusted_developer_machine_signed_manifest
```

## Limitations

Developer-machine signing is simpler than dual hardware-token signing. It can verify that a manifest was signed by an enrolled developer-machine key, and it prevents normal source changes from being silently trusted. It cannot fully protect against a compromised enrolled developer machine.

This feature is CISA/NIST/DoD/CMMC readiness evidence support only. It is not CISA approved, DoD approved, CMMC certified, NIST compliant, or government approved.
