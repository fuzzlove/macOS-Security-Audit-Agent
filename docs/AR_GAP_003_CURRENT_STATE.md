# AR-GAP-003 Current State

Build identity: commit `ffe40a5c73f86e909335b0483e3d5db6105ff069`, CPython 3.14.6, macOS 15.7.2 arm64, SDK 15.5. Only Command Line Tools are selected and `security find-identity` reports zero valid identities.

Implemented: native exact-action boundary; UID/start/path/device/inode/SHA-256 revalidation; stopped/resumed/zombie verification; fixed native lease watchdog core; safe self-contained fixture; Python evidence-first coordinator; sensor-only bounded identity registry; synchronous native lease-journal model; boot reconciliation; bounded/replay-resistant protocol; derived readiness calculation; source-safe doctor; native arm64 containment-helper Mach-O with public XPC listener peer-requirement API and fail-closed development behavior.

Native build evidence: `/tmp/MSAAContainmentHelper`, SHA-256 `7e8f11ebdec290b5415cc135054999b1296eacbee1bfa37ccdb11ba567eb4fcc`, arm64. Its linker-generated signature is ad hoc (`flags=adhoc,linker-signed`), Team ID absent, CDHash `1c905152fc36c801c4e5921c8c7a623ed9592103`; therefore `DEVELOPER_ID_SIGNED=false`.

Mock or source tested: sensor registration authentication flag, two-phase durable prepare, transition ordering, expiry, identity mismatch, boot change, PID reuse, critical-process rejection, replay, malformed payloads, native pause/resume/termination of a self-created fixture.

Not live production tested: Developer ID signatures, installed helper, frozen signed engine, Mach XPC round trip, listener peer requirement, real sensor target audit token, live CDHash/signing comparison, guardian survival after helper SIGKILL, launchd restart, disposable-host reboot, signed fixture identity matrix.

`ACTIVE_CONTAINMENT_READY` is false.
