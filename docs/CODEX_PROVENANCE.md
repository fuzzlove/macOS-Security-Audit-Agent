# Codex Provenance

Codex-assisted changes are recorded as advisory provenance metadata, not cryptographic trust.

Create a provenance record:

```bash
python3.12 -m mac_audit_agent.integrity codex-provenance create --operator "Liquidsky Codex Session" --summary "Release build integrity update"
```

Records include:

- Codex operator label
- metadata-only account reference when provided
- prompt/change summary
- changed file list
- git commit before/after
- developer review metadata
- approved change ID when available

Codex metadata can explain how a change was produced, but it does not sign or endorse a build. Cryptographic trust comes from the enrolled developer-machine identity, the canonical manifest hash, and the developer-machine signature.

MSAA provides local integrity, signing, and readiness evidence. This does not imply CISA, DoD, NIST, CMMC, Yubico, OpenAI, or government approval, certification, or endorsement.
