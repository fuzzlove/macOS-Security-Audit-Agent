# Anti-Ransomware UAT

Run source tests and native self-tests before disposable-host validation. A healthy JSON result must be generated from live signed artifacts and cannot be injected as a fixture. Do not accept `PROTECTED` unless every predicate in `evaluate_readiness` passes.

External-gate checks include Developer ID signature, hardened runtime, exact entitlement, notarization/stapling, system-extension activation, Full Disk Access, MDM approval if managed, live event reception, authenticated helper, pause/resume/termination fixtures, restart/reboot reconciliation, and no orphaned suspension.

Current source/development builds are expected to report AR022 and `UNINSTALLED` or `DEGRADED` operational state.
