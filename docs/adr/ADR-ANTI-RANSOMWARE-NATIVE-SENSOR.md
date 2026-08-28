# ADR: Anti-Ransomware Native Sensor

Status: accepted architecture; production approval blocked externally. Date: 2026-07-10.

Selected: Option A, an Endpoint Security system extension embedded in the signed app, with a separate frozen Python 3.14.6 system engine and per-user notifier. Option B, a LaunchDaemon ES client, remains a compatibility path only if entitlement/deployment review requires it. Option C is rejected because GIL, Python crashes, PyInstaller lifecycle, and callback timing expand the privileged deadline-critical boundary. Option D is supported only as `EXTERNAL_TELEMETRY_OBSERVATION`, never equivalent containment.

Minimum planned OS is macOS 13. Apple Silicon is the only tested architecture; Intel is blocked hardware. Production needs Apple Endpoint Security entitlement, Developer ID identities, provisioning, privacy/MDM approval, authenticated XPC audit-token and code-requirement validation, stable helpers, explicit update/rollback/uninstall, and live disposable-Mac testing. Source mode is `SAFE_SIMULATION_ONLY` or degraded observation. Frozen mode uses stable bundled executables without external Python or PYTHONPATH.
