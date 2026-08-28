# Endpoint Security Contribution Request

Requested component: `com.fuzzlove.MacAuditAgent.EndpointSecuritySensor`. The production Team ID must be supplied by the Apple Developer Account Holder and must replace the unresolved canonical Team ID only through the controlled production configuration.

Required entitlement: `com.apple.developer.endpoint-security.client` on the signed sensor. This enables attributed process/file notification and, after separate containment qualification, cached authorization decisions. The request should describe metadata collection, exclusion of full user-file contents, bounded retention, student/government privacy controls, accessible notices, safe containment, update/uninstall procedures and disposable-host test plan.

Return only the signed sensor, public certificate chain, Team ID, signing identifier, designated requirement, CDHash, entitlements output, SHA-256, build metadata and non-secret Apple approval evidence. Never provide a private key, p12 password, App Store Connect private key, Apple Account/app-specific password or Keychain export.

Verify with:

```text
codesign --verify --strict --verbose=4 <sensor>
codesign -d --verbose=4 <sensor>
codesign -d --entitlements :- <sensor>
spctl --assess --type execute --verbose=4 <sensor>
shasum -a 256 <sensor>
```

Entitlement approval does not itself prove TCC approval or a live Endpoint Security connection.
