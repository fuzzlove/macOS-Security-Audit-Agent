# Integrity Recovery

Use recovery when Integrity Health reports manifest path divergence, missing canonical manifest, missing developer-machine signature bundle, or developer-machine enrollment failure.

Discover manifests:

```bash
python3.12 -m mac_audit_agent.integrity discover
```

Inspect status:

```bash
python3.12 -m mac_audit_agent.integrity status --verbose
```

Repair status:

```bash
python3.12 -m mac_audit_agent.integrity repair-status --policy dev --discover --migrate-legacy --exclude-generated --developer-machine
```

Recovery rules:

- canonical manifest is `mac_audit_agent/integrity/integrity_manifest.json`
- legacy manifests are diagnostic inputs only
- multiple legacy candidates require manual review
- generated artifacts are excluded before signing
- source/security changes require approved change evidence
- an enrolled trusted developer machine is required before a new trusted manifest can be signed

MSAA provides local integrity, signing, and readiness evidence. This does not imply CISA, DoD, NIST, CMMC, Yubico, OpenAI, or government approval, certification, or endorsement.
