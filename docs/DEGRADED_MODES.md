# Degraded Modes

Capability states are explicit: `AVAILABLE`, `DEGRADED`, `PERMISSION_REQUIRED`, `DEPENDENCY_MISSING`, `UNSUPPORTED_OS`, `UNSUPPORTED_ARCHITECTURE`, `UNSUPPORTED_PYTHON`, `NOT_INSTALLED`, `NOT_SIGNED`, `NOT_ENTITLED`, `NOT_LOADED`, `FAILED`, and `UNKNOWN` only when evidence cannot be made more precise.

Missing PySide6 leaves CLI/doctor operational. Missing native sensor or entitlement yields observation-only anti-ransomware behavior. Missing Full Disk Access limits affected collectors. Missing optional exporters or network tools disables only those capabilities. No fallback claims prevention or containment it cannot provide.
