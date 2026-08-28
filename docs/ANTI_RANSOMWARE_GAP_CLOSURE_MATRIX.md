# Anti-Ransomware Gap Closure Matrix

Machine-readable evidence: `ANTI_RANSOMWARE_GAP_CLOSURE_MATRIX.json`.

| Gap | Current state | Works | Missing for closure |
|---|---|---|---|
| 001 sensor | IMPLEMENTED, UNIT_TESTED, BLOCKED_EXTERNAL_APPROVAL/CREDENTIALS | Original C source; strict syntax validation; native sequence/deadline/queue tests; bounded 4,096-message retained ownership with one serial drain and release paths | Full Xcode/framework, entitled Developer-ID signed artifact, FDA/PPPC, live events/deadlines/restart |
| 002 IPC | IMPLEMENTED, UNIT_TESTED, NOT_VERIFIED | Connection-bound replay/expiry, role-scoped exact-identity actions, native audit-token SecCode/Team/signing/designated-requirement/ad-hoc validation source | Signed native XPC listener and live signed/unsigned/wrong-team adversarial clients |
| 003 containment | IMPLEMENTED, UNIT_TESTED, INTEGRATION_TESTED, NOT_VERIFIED | Durable evidence-first coordinator; executed safe local native fixture (not privileged live qualification); native UID/start/path/device/inode/SHA-256 revalidation; stopped/resumed/zombie verification; fixed 256-lease monotonic watchdog; zero suspended fixtures | Signed privileged service integration, authenticated IPC, audit-token generation revalidation, service restart/reboot qualification |
| 004 vault | IMPLEMENTED, UNIT_TESTED, INTEGRATION_TESTED, NOT_VERIFIED | Schema v3; transactional migration and verified-backup recovery; disk-full rollback; bounded lock recovery; read-only/corruption/downgrade refusal; restart/concurrency; child-preserving updates; sanitized notifications; retention/export/hash chain | Installed root ownership and real non-root notifier denial |
| 005 correlation | IMPLEMENTED, UNIT_TESTED | Bounded 5s/30s/5m/30m/24h monotonic process-tree engine, multi-directory/volume summaries, gap-aware visibility | Full slow-behavior and false-positive corpus measurement |
| 006 sabotage | IMPLEMENTED, UNIT_TESTED | Non-destructive snapshot/service command fixtures | Live native event inputs and broader maintenance corpus |
| 007 notifier | IMPLEMENTED, UNIT_TESTED, NOT_VERIFIED | Sanitized bounded queue; durable replay, delivery and acknowledgement states | Authenticated XPC, live login/logout replay, accessible render |
| 008 deployment | DESIGNED, PYTHON_BUILT, BLOCKED_CREDENTIALS | Stable path/plist and MDM/PPPC templates | Signed app/pkg, entitlement, notarization, install/update/rollback/uninstall |
| 009 accessibility | IMPLEMENTED, UNIT_TESTED, NOT_VERIFIED | Native Qt controls, names, no modal/timeout | Current manual VoiceOver/keyboard/scaling/AT evidence |
| 010 performance | IMPLEMENTED, UNIT_TESTED, NOT_VERIFIED | Python characterization; 5-second bounded observer lifecycle run with zero drops and stable threads/descriptors | Approved budgets, native metrics, long-duration soak and hardware matrix |

No gap is closed. `DEGRADED_OBSERVATION_READY` is true: the explicit-root metadata observer is implemented and tested, but it has delayed events, incomplete process/root attribution, possible event loss, and no preemptive containment. All Endpoint Security and higher readiness gates remain false.
