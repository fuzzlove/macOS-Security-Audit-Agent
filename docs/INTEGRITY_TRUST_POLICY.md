# Integrity Trust Policy

The canonical trust policy is `mac_audit_agent/integrity/trust_policy.json`.

The policy records:

- required signer: one active trusted developer-machine identity
- allowed developer IDs
- enrolled public certificates/keys and certificate fingerprints
- required manifest hash, build ID, git commit, and policy bindings
- whether Codex provenance is required as metadata

Trust rule:

A manifest update is trusted only when protected files match the manifest, source changes are approved, the developer-machine identity is active, the enrolled developer-machine key signs the manifest hash, and Pre-UAT validates the same canonical manifest.

Legacy paths are discoverable but ignored as active trust anchors:

- `mac_audit_agent/integrity/integrity_manifest.json`
- `mac_audit_agent/integrity/integrity_manifest.signature.json`
- `mac_audit_agent/integrity/trusted_developer_machines.json`
- `mac_audit_agent/integrity/release_manifest.json`
- `mac_audit_agent/integrity/development_manifest.json`
- runtime install manifests

MSAA provides local integrity, signing, and readiness evidence. This does not imply CISA, DoD, NIST, CMMC, Yubico, OpenAI, or government approval, certification, or endorsement.
