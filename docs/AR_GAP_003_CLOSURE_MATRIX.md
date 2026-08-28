# AR-GAP-003 Closure Matrix

| Requirement | Current evidence | State | Required closure evidence |
|---|---|---|---|
| Signed helper | Native arm64 Mach-O builds; public XPC peer requirement; fail-closed development artifact; ad-hoc linker signature only | NATIVE_BUILT, BLOCKED_CREDENTIALS | Developer ID, hardened signature, installed artifact |
| XPC | Audit-token SecCode source and strict protocol | NOT_VERIFIED | Installed signed-engine round trip and adversarial clients |
| Target identity | Sensor-only registry; native UID/start/file/hash checks | IMPLEMENTED | Live ES audit token, pidversion, CDHash, signing and boot comparison |
| Watchdog | Fixed native core plus FULL-sync journal | IMPLEMENTED | Separate guardian surviving helper SIGKILL |
| Crash/restart | Deterministic reconciliation models | NOT_VERIFIED | launchd helper/engine fault matrix |
| Reboot | Boot mismatch closes without signal | BLOCKED_HARDWARE | Real disposable-host reboot |
| Signed fixtures | Self-contained unsigned fixture executed | BLOCKED_CREDENTIALS | Developer-ID identity/replacement/re-exec matrix |
| Cleanup invariant | Local tests report zero suspended fixtures | UNIT_TESTED | Zero after every installed fault-injection case |

No mandatory live state is inferred from source or mock evidence. `ACTIVE_CONTAINMENT_READY=false`.
