# BlockBlock Design Review and MSAA Translation

## Scope and licensing boundary

The locally supplied BlockBlock repository was reviewed as a reference implementation for macOS persistence monitoring. It is GPL-3.0 licensed, while MSAA declares MIT licensing. No BlockBlock source, watch-list expressions, UI assets, XPC protocols, or implementation code were copied. The MSAA changes are an independent Python implementation of general security design ideas: monitor persistence changes, retain attribution, authenticate privileged boundaries, deduplicate related events, and show actionable context.

Reviewed areas included the Endpoint Security file monitor, event and process models, plugin/watch-list loading, LaunchAgent/LaunchDaemon and BTM handling, rule matching, event deduplication, daemon-to-user XPC boundary, client signing validation, alert window, signing and ancestry views, installer/helper lifecycle, and failure paths for unavailable user clients.

## Architecture comparison

| Area | BlockBlock observation | Existing MSAA posture | MSAA decision |
| --- | --- | --- | --- |
| Event source | Endpoint Security notifications provide near-real-time file/process attribution. | Portable snapshot polling plus an optional native event bridge. | Keep the entitlement-free fallback; expand native event context and snapshot change coverage. |
| Persistence coverage | Focused plugins for launchd, BTM, cron, extensions, login helpers, and selected processes. | Broad scanners cover more mechanisms, but the lightweight daemon watched only launch items and login-item additions. | Add daemon snapshots for privileged helpers, extensions, cron, startup items, and BTM state. |
| Change semantics | Create, write, and rename events are evaluated. | Lightweight monitoring emitted only additions. | Detect additions, content/identity modifications, and removals. |
| Attribution | Event includes process path, PID, arguments, signing identity, team ID, platform status, and ancestry. | Native frame supported process/PID/parent but did not retain the complete bounded context. | Add bounded arguments, ancestry, signing ID, team ID, and platform-binary status. |
| Deduplication | Related events compare plugin, process, destination, target, and a short time window. | Database correlation, evidence hashes, cooldowns, grouping, and durable alert traces are more comprehensive. | Retain MSAA implementation. |
| Undelivered alerts | Source contains an unfinished in-memory undelivered-alert path; failed delivery advances plugin state. | SQLite-backed event queue and per-user receipt database survive restarts. | Retain MSAA implementation; do not regress to memory-only delivery. |
| Rules | Per-process allow/block rules prefer signing identity and validate that signed code remains valid. | Detection rules, trust scoring, acknowledgement, and incident workflow are separated from remediation. | Preserve evidence-first behavior; signing-aware remediation authorization remains a future native-helper concern. |
| Privileged IPC | XPC clients are constrained using audit tokens, code validity, hardened runtime, identifier, and signer requirements. | Native containment has an authenticated protocol; notifier transport is read-only database plus per-user receipts. | Preserve strict identity checks for privileged helpers and document this as mandatory for future ES integration. |
| Remediation | A block may unload a job, delete its plist, and kill matching processes immediately. | Remediation is explicit, auditable, and designed around evidence preservation. | Do not adopt automatic destructive blocking. Offer review and authorized remediation only. |
| Alert UX | Shows process, PID, arguments, target, signing status, timestamp, VirusTotal action, ancestry, and temporary/permanent scope. | Durable cards emphasized severity, authorization, risk, and evidence confidence. | Add responsible process, persistence path, code signer, and ancestry to the visible card when available. |
| OS evolution | Plugin availability is gated by macOS major version; BTM replaces older login-item monitoring on newer releases. | Scanner coverage and capability diagnostics degrade independently. | Retain capability-based degradation; artifact monitoring is filesystem-based and does not claim BTM attribution without native events. |

## Implemented changes

1. Launch item content is SHA-256 fingerprinted. Existing LaunchAgents and LaunchDaemons now emit modification events when their parsed state or source content changes, and removal events when they disappear.
2. The background daemon inventories privileged helpers, kernel extensions, system extensions, cron tabs, legacy startup items, and per-user Background Task Management artifacts. Each bounded artifact snapshot records a fingerprint, size, modification time, mode, and owner UID.
3. Artifact additions, modifications, and removals receive explicit persistence rules, verification steps, false-positive guidance, MITRE persistence mappings, durable metadata, evidence hashes, and correlation identifiers.
4. Privileged helpers and extensions are elevated to critical severity when added or modified. Removals remain medium because they can be either legitimate cleanup or defense evasion and need timeline correlation.
5. Native persistence frames accept bounded process arguments (64 entries), ancestry (32 entries), signing identity, team ID, and platform-binary status. This context remains inside the persisted event metadata.
6. Alert cards show the responsible process, persistence path, signing identity/team, and a bounded ancestry chain when present.
7. Native event capability declarations include launch-item modifications/removals and generic persistence artifact lifecycle events.

## Deliberately not adopted

- MSAA does not copy or compile BlockBlock code, assets, plugins, or watch lists.
- MSAA does not silently allow an event merely because the GUI client is unavailable. Events remain durable for later delivery.
- MSAA does not automatically delete plists, unload services, or kill processes from a detection callback. That can destroy evidence, interrupt legitimate software, and create denial-of-service risk.
- MSAA does not treat a signing identity as permanent trust. Signatures are evidence, not an allow decision; target hashes, ownership, authorization, and current validity must also be considered.
- MSAA does not claim Endpoint Security real-time guarantees from the Python snapshot fallback. Polling can observe a net state change but may miss a create-and-remove action between intervals. The native bridge is the supported path for entitled event sources.
- MSAA does not send file hashes or artifacts to VirusTotal automatically. External reputation checks require explicit user action and privacy disclosure.

## Remaining native roadmap

The strongest future improvement requires an Apple-approved Endpoint Security entitlement and a signed native sensor. That sensor should emit versioned, authenticated frames into the existing native bridge with source audit token, responsible PID, parent chain, arguments, signing identity, team ID, code-signing flags, destination path, event action, and event sequence number. It should mute its own writes, bound caches, release retained ES messages on every path, expose dropped-event counters, and never accept destructive commands over the event channel. The existing MSAA daemon and durable notifier can consume those frames without making GUI availability a security dependency.

Any privileged control channel must authenticate the caller at the kernel-provided identity boundary, verify current code validity and designated requirements, reject replay, log authorization decisions, and keep read-only event transport separate from remediation commands.
