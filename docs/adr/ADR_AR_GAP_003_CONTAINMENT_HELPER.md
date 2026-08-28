# ADR: AR-GAP-003 Containment Helper

Decision: use a dedicated native LaunchDaemon registered through the signed application’s supported ServiceManagement workflow, with bundle ID `com.fuzzlove.MacAuditAgent.ContainmentHelper` and Mach service `com.fuzzlove.MacAuditAgent.ContainmentHelper.xpc`. The frozen system engine identity is `com.fuzzlove.MacAuditAgent.SystemEngine`.

The helper accepts incident/event references, never a bare PID. An authenticated sensor populates a bounded short-lived identity registry. The helper owns caller authentication, target resolution, native revalidation, synchronous lease journal, guardian/watchdog, fixed action enum, verification and reconciliation. Python retains detection and policy responsibilities.

Source mode cannot connect to production containment. The helper contains no Python, Qt, network client, shell execution, arbitrary signal, plugin loader or generic filesystem API. Production registration awaits Developer ID credentials and explicit disposable-host installation authority.

Rejected alternatives: embedding Endpoint Security callbacks in Python couples GIL/crash timing to security deadlines; a Python signal helper cannot establish the required native trust boundary; a dispatch timer alone cannot survive helper SIGKILL. The selected crash-survival direction is a one-purpose per-lease guardian with a fixed identity and maximum deadline, bounded globally by the helper.
