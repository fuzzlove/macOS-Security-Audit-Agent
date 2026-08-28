# Anti-Ransomware External Gates

`APPLE_ENDPOINT_SECURITY_ENTITLEMENT`: owner is the Apple Developer Account Holder; evidence is an approved, correctly signed sensor. `DEVELOPER_ID_SIGNING`: owner is the release-signing engineer; evidence is hardened timestamped component signatures. `MACOS_PRIVACY_APPROVAL`: owner is the local administrator or MDM/PPPC operator; it is distinct from entitlement approval and cannot be granted by pip, sudo GUI execution or direct TCC database changes. `DISPOSABLE_HOST_LIVE_TEST`: owner is the authorized host operator; evidence includes installed service, live connection, harmless fixture event and cleanup. `ACTIVE_CONTAINMENT_QUALIFICATION`: requires the signed helper/engine chain and fault tests.

While these gates are open, safe simulation and degraded observation continue. Status remains `DEGRADED`, with no process-containment claim.

## Runtime evidence contract

The installed native sensor writes its live connection result to the root-owned runtime location reported by `sensor_details.health_path`. MSAA accepts that record only when it is a regular file, owned by root, not group/world writable, no older than 30 seconds, and bound to the current build and boot session. Entitlement acceptance, privacy approval, subscriptions, sequence tracking, and a live fixture event are separate booleans in that record. Development-observer validation additionally requires a fresh System Monitor heartbeat and challenge-bound receipts for all harmless fixture stages. A repository artifact, launchd plist, root execution, mock event, generic filesystem timestamp, stale heartbeat, or embedded entitlement key cannot substitute for this evidence.
