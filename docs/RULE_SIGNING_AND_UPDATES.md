# Detection Rule Signing and Updates

Exact SHA-256 indicators remain available independently of YARA. MD5 and SHA-1 are correlation-only. Optional YARA scanning is bounded by file size and timeout and never runs in the Endpoint Security callback.

Trusted rule packages use canonical JSON and Ed25519 signatures through `cryptography`, unique rule identifiers, expiration, monotonic integer version, and rollback/replay rejection. Unsigned, expired, duplicated, malformed, tampered, or obsolete packages are rejected. Application and rule signing roles must remain separate in production. Normal runtime never installs Python packages or silently trusts new keys.
