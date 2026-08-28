# Apple Developer Contribution Packet

1. Confirm production Team ID and ownership of the `com.fuzzlove` identifiers.
2. Select valid Developer ID Application and Installer identities with private keys in a controlled Keychain.
3. Configure identity names through environment variables; do not export keys.
4. Run contribution preflight and retain its redacted JSON.
5. Build, sign inside-out, and verify every component explicitly.
6. Extract Team ID, signing ID, designated requirement, CDHash, flags, entitlements and SHA-256 from the signed engine; generate the exact helper peer requirement from this evidence.
7. Configure only a `notarytool` Keychain profile name, submit, require Accepted, staple and validate.
8. Return signed artifacts, public certificate chain, verification output, source commit and build metadata. Never return private credential material.
