# MSAA Release Process

1. Confirm the working tree is clean.
2. Run compile and tests.
3. Run full Pre-UAT.
4. Build release artifacts.
5. Run `twine check`.
6. Run clean install verification.
7. Generate and sign the release manifest.
8. Sign final `dist/` artifacts.
9. Verify release integrity.
10. Upload only the signed artifacts.

One-command wrapper:

```bash
./scripts/msaa_release_sign.sh 1.0b
```

The wrapper aborts on dirty git state or failed verification. It does not print private key material.

Manual integrity signing:

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

python3.12 -m mac_audit_agent.integrity verify --policy public_release --strict
python3.12 -m mac_audit_agent.integrity doctor --policy public_release
```

The release manifest signs only the deterministic `payload` section. The detached signature bundle and display `metadata` are not part of the signed payload. Verification must fail closed for missing public keys, modified manifests, stale manifests, or tracked file hash drift.
