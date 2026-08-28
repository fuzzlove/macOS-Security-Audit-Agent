# Integrity Release Signing

MSAA release signing is an explicit trust gate. It clears release integrity warnings only when the current files and artifacts match signed manifests. It does not trust modified files automatically.

## Key Rules

- Never commit the private release signing key.
- Store the private key outside the repo, for example `~/.msaa/keys/msaa_release_ed25519_private.pem`.
- The public key may be bundled at `mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem`.
- Source development mode may be unsigned without being treated as malicious.
- Public release mode requires signed manifests and matching hashes.

## Generate Keys

```bash
python3 -c "from mac_audit_agent.integrity.signing import generate_keypair; generate_keypair()"
```

This creates a private key under `~/.msaa/keys/` and a public key under `mac_audit_agent/integrity/trust/`.

## Sign a Final Release

```bash
python3 -m mac_audit_agent.integrity.release_sign all \
  --version 1.0b \
  --mode public_release
```

Use `MSAA_RELEASE_SIGNING_KEY_PATH` or `MSAA_RELEASE_SIGNING_KEY` if the private key is not in the default location.

## Verify

```bash
python3 -m mac_audit_agent.integrity.release_verify --strict
```

Expected valid release state:

```text
trusted_signed_release
```

If any signed file changes after signing, verification fails with a release mismatch state.

## Sign Dist Artifacts

Build first, then sign the exact files that will be uploaded:

```bash
python3 -m build
python3 -m twine check dist/*
python3 -m mac_audit_agent.integrity.release_sign sign-artifacts --version 1.0b --dist dist
```

If anything in `dist/` changes afterward, run artifact signing again.

## PyPI Trusted Publishing

Prefer PyPI Trusted Publishing over long-lived PyPI API tokens. PyPI provenance and local MSAA release manifests are separate trust layers.

## macOS App Signing

PyPI source/wheel releases do not require macOS app signing. If distributing a `.app`, DMG, or installer, use `scripts/sign_macos_app.sh` with:

- `MSAA_CODESIGN_IDENTITY`
- `MSAA_NOTARY_PROFILE` if notarization is configured
