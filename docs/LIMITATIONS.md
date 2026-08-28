# Limitations

- MSAA cannot guarantee that a device is uncompromised.
- A passing control does not prove the absence of all attacks.
- Simulated evidence is not production evidence.
- Standards mappings do not constitute certification.
- Local software cannot establish absolute trust when the underlying platform is fully compromised.
- Recovery of an MSAA fixture does not prove full-system recoverability.
- Endpoint Security functionality depends on supported APIs and required entitlements.

The initial native persistence implementation is a bounded atomic JSONL foundation,
not an immutable database or high-volume event store. Secure Enclave and Keychain
production signers, authenticated extension IPC, full collector implementations,
and validated OSCAL output remain future integration work. The current development
host also has mismatched Swift compiler/SDK versions, so the new package cannot be
reported as compiled until that toolchain is repaired.
