# Native Assurance Security

The native assurance core is deterministic, local, and independent of AI and network
services. It uses fixed executable URLs and argument arrays without a shell, bounded
output, typed errors, atomic writes, strict profile versions, SHA-256 chains, and
public-key-verifiable Ed25519 checkpoints. The bundled deterministic signer is only
for tests and identifies itself as non-hardware-backed.

Production work must add a Keychain-protected signer and, when supported, a separate
Secure Enclave signer. Software fallback must never be described as hardware-backed.
Endpoint Security integration must use the public API with the required entitlement
and authenticated versioned IPC; no bypass or simulated-as-real evidence is allowed.
