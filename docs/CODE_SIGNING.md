# Code Signing

Signing identities are supplied through `MSAA_DEVELOPER_ID_APPLICATION_IDENTITY`; no private material belongs in the repository.

```bash
export MSAA_DEVELOPER_ID_APPLICATION_IDENTITY='Developer ID Application: …'
scripts/sign-app.sh 'dist/arm64/Mac Audit Agent.app'
codesign --verify --deep --strict --verbose=4 'dist/arm64/Mac Audit Agent.app'
```

Nested native libraries are signed before the outer app with hardened runtime. Endpoint Security and privileged helpers use separately reviewed entitlements and identities.

## Signing readiness

MSAA can inspect a public certificate and verify that its matching private key is available as a code-signing identity:

```bash
scripts/apple-signing-readiness.sh "$HOME/Downloads/development.cer"
```

The current certificate `Apple Development: Joe McPeters (CDLLV82T6K)` belongs to Team `QPWZZT9ZZK` and is suitable for local development signing only. The `.cer` contains the public certificate, not the private key. Export the matching identity from the Mac where the certificate request was created as a password-protected `.p12`, transfer it securely, and import it into the login keychain. Never commit the `.p12` or its password.

After the identity is installed, a local ClickFix Guard build can use:

```bash
export MSAA_SIGNING_CERTIFICATE="$HOME/Downloads/development.cer"
export MSAA_CODESIGN_IDENTITY='Apple Development: Joe McPeters (CDLLV82T6K)'
export MSAA_TEAM_IDENTIFIER='QPWZZT9ZZK'
native/ClickFixGuard/build.sh
```

Distribution outside local development requires a `Developer ID Application` identity and notarization credentials. Endpoint Security additionally requires Apple approval and a provisioning profile whose Team ID matches the certificate and whose entitlements authorize `com.apple.developer.endpoint-security.client`. Validate that separate gate with:

```bash
scripts/apple-signing-readiness.sh "$MSAA_SIGNING_CERTIFICATE" \
  --require-endpoint-security --profile "$MSAA_PROVISIONING_PROFILE"
```

Editing an entitlement plist, importing a public certificate, or running as root does not grant a restricted entitlement.

## Automated Endpoint Security profile creation

After Apple has approved and enabled Endpoint Security on the exact sensor App ID, `scripts/create_endpoint_security_profile.py` can create and download the profile through Apple's App Store Connect API. It never requests or changes the managed-capability approval and never stores an API token or private key in the repository.

Create an App Store Connect API key with Certificates, Identifiers & Profiles access, protect the downloaded `.p8` with mode `0600`, and set only its path and public identifiers:

```bash
export ASC_KEY_ID='KEY_ID'
export ASC_ISSUER_ID='ISSUER_UUID'
export ASC_PRIVATE_KEY_PATH="$HOME/Documents/AuthKey_KEY_ID.p8"

python3 scripts/create_endpoint_security_profile.py --dry-run
python3 scripts/create_endpoint_security_profile.py
```

The development workflow uses the local Mac's provisioning UDID and refuses to register it unless `--register-current-mac` is explicitly supplied. Use `--kind developer-id --certificate /path/to/developer-id.cer` to create a `MAC_APP_DIRECT` profile for distribution. The resulting profile is accepted only if its Team ID, exact App ID, signing certificate, expiration, and `com.apple.developer.endpoint-security.client` entitlement all verify locally.

Keep Apple leaf signing certificates set to **Use System Defaults** in Keychain Access. Marking an Apple Development or Developer ID leaf certificate as **Always Trust** installs a `Trust as Root` override, breaks the WWDR/Developer ID chain, and commonly causes `codesign` to return `errSecInternalComponent`. Install the applicable Apple intermediate certificate instead of weakening leaf trust.
