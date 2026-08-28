# Endpoint Security Entitlement Readiness

Bundle placeholders: `TEAM_ID`, `com.example.msaa`, `com.example.msaa.AntiRansomwareSensor`. Purpose: detect ransomware-like file behavior and recovery impairment using minimal process/file metadata. Explicit exclusions: full file contents, arbitrary environments, passwords, student documents, message contents, and network payloads. Production requires Apple entitlement approval, provisioning, Developer ID signing, system-extension activation, privacy approval, and live disposable-Mac tests. The project owner reported Apple approval on 2026-08-24; repository verification remains `BLOCKED_CREDENTIALS` until the approved profile and matching signing identity are available on the build Mac.

## 2026-08-24 implementation evidence

- Framework-independent native sequence, deadline, bounded-queue, rejection, drain, and shutdown-release tests pass.
- The full sensor passes strict warnings-as-errors syntax validation.
- The callback retains before return and releases on accepted, rejected, drained, and shutdown paths.
- The native sensor now links against the public `libEndpointSecurity` SDK
  stub. The earlier `framework 'EndpointSecurity' not found` result was a build
  configuration error: Endpoint Security is distributed as a system library,
  not a framework.
- The build now produces an app-like daemon bundle, as required to embed the provisioning profile that authorizes a restricted entitlement.
- The release signer validates the exact Team ID, App ID, Endpoint Security authorization, and profile certificate before signing, then verifies the signature's extracted entitlements.
- No signing identity or provisioning profile is present on the current build Mac, so a production signature has not been produced.
- Entitlement acceptance, Full Disk Access, live connection/events, AUTH deadlines, and restart remain unverified.

Entitlement presence and privacy approval are evaluated independently. A plist key, root execution, or displayed instructions do not establish either. Only the entitlement extracted from the signed installed artifact can establish `entitlement_embedded`; only current native connection evidence can establish `entitlement_accepted`; only current approved service evidence can establish privacy approval.
