# Anti-Ransomware Architecture and Limitations

The selected production boundary is a dedicated signed and entitled Endpoint Security sensor plus a Python 3.14 system engine and an unprivileged notifier. Direct production `ctypes`/`cffi` Endpoint Security callbacks are rejected because callback deadline, message lifetime, GIL, crash isolation, entitlement, and signing risks belong in a minimal native process.

Current implementation is `DEGRADED_OBSERVATION_ONLY`. It provides independent statistics, compatibility windows, explainable decisions, health output, safe synthetic fixtures, CLI, and a nonblocking UI category. It provides no preemptive denial or live containment.

The native protocol is bounded JSON for development and prohibits file contents, arbitrary environments, and Python serialization. Production IPC must authenticate code identity and audit tokens, bind decisions to incident/event/process generation/boot session/nonces, reject replay, and meet Endpoint Security deadlines.

Apple requires the `com.apple.developer.endpoint-security.client` entitlement; source presence does not establish entitlement availability, signing, Full Disk Access, or production approval.

## Build evidence

The C sensor scaffold passes its native safety tests and builds with strict
warnings against the public `libEndpointSecurity` SDK stub. The earlier
`framework 'EndpointSecurity' not found` failure was caused by treating the API
as a framework instead of a system library. A successful unsigned build does
not establish Apple entitlement approval, code signing, Full Disk Access,
system-extension activation, or live event delivery. Production still requires
the Apple-granted entitlement on the sensor's App ID/profile, a matching signing
identity, a signed host and extension, and live deadline/message-lifetime tests.
Disabling SIP is not an accepted production remediation.

## Implemented Python safety foundation

- Large-file sampled transitions, high-entropy transitions, extension changes, original deletion, rename-over-original, canary and ransom-note signals.
- Process-tree aggregation across multiple child identities.
- Identity-bound rules that require hashes and managed approvals.
- PID-generation revalidation before containment.
- Critical-continuity exclusion and evidence-before-action enforcement.
- One-owner bounded analysis queue with explicit drop counters and bounded shutdown.
- Transactional SQLite evidence with bounded WAL configuration and per-record SHA-256 verification.

Official guidance mapping is supporting evidence only: NIST CSF 2.0 Govern/Protect/Detect/Respond/Recover; NIST SP 800-61 Rev. 3 preparation and incident lifecycle; NIST IR 8374 Rev. 1 ransomware risk outcomes; CISA StopRansomware prevention, detection, backups, response, and reporting preparation; CISA K–12 MFA, KEV remediation, tested backups, exercises, and training. Installation does not establish organizational compliance.
