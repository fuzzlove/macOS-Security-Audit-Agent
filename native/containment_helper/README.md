# MSAA Containment Helper

Native target ID: `com.fuzzlove.MacAuditAgent.ContainmentHelper`. Mach service: `com.fuzzlove.MacAuditAgent.ContainmentHelper.xpc`.

The development artifact supports only `--self-check`. When launched as a service without an embedded exact engine requirement it fails closed with `AR-CNT-002`. Its XPC listener uses the public macOS 14.4 peer-code-signing requirement API. Production action handling remains disabled until the sensor registry, journal, guardian and Developer ID requirement are linked and qualified.

This target contains no Python, Qt, network client, plugin loader, shell execution, arbitrary PID API or arbitrary signal API.
