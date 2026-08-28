# MSAA Native Evidence Format

Schema 1.0 uses UTF-8 JSON with sorted keys, explicit nulls, and UTC ISO-8601
timestamps truncated to millisecond precision. Binary values use Base64. Each JSONL
record includes a monotonically increasing sequence, the previous SHA-256 digest,
and its own SHA-256 digest calculated with `recordDigest` set to the empty string.

An export contains `manifest.json`, control definitions, evaluations,
`evidence-events.jsonl`, collector health, validation results, exceptions, framework
mappings, checkpoints, signature metadata, a public verification key, and README.
The manifest contains each payload digest. Its digest is signed with Ed25519 by the
test signer; production signers must accurately identify Keychain or Secure Enclave
protection. The local store is tamper-evident, not immutable.
