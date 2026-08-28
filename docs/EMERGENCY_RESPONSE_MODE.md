# Emergency Response Mode

Emergency Response Mode is an orchestration layer over MSAA's shared event database, ransomware containment boundary, persistence intelligence, network controls, and evidence collectors. It is intentionally separate from `emergency_lockdown.py`, which assists with Apple's Lockdown Mode and is not an incident-response workflow.

## Safety contract

- Every state-changing operation requires a named, authenticated administrator authorization with an expiry.
- Failed authorization is itself recorded as a critical shared security event.
- Evidence must exist and its SHA-256 must verify before containment, recovery, or exit.
- Snapshot collectors record explicit per-collector errors; partial collection is never reported as complete.
- Network and process changes are only available through installed privileged adapters. Source mode supplies no implementation that can signal processes or alter interfaces/firewall state.
- Process response requires a confidence score of at least 80 plus PID, executable path, SHA-256, and process start time. Installed adapters must independently revalidate identity and authorization.
- Network exit requires verified restoration of the captured previous state.
- Evidence is never erased when the workflow returns to `NORMAL`.

## States

`NORMAL`, `WARNING`, `INVESTIGATION`, `CONTAINMENT ACTIVE`, and `RECOVERY MODE` are the canonical display values. Activation enters `INVESTIGATION`; verified containment enters `CONTAINMENT ACTIVE`; an authorized responder explicitly enters recovery and exits only after evidence and network restoration checks.

## Integration boundary

`EmergencyResponseManager` records `BackgroundMonitorEvent` objects in the existing searchable event database. Its structured metadata contains the incident, responder, authorization source, affected processes/files, network state, evidence reference, result, analyst notes, score impact, and recommended action. Ransomware or other alert workflows may activate it by passing their event ID as `trigger_event_id`; activation is never anonymous.

## Deployment requirements

Production GUI and command surfaces must obtain authorization from MSAA's approved administrator authentication service and must inject the signed network/process containment adapters. Until those adapters and authentication service are configured and qualified, the safe supported workflow is activation, evidence collection, review, timeline export, and audit inspection. MSAA must not label source-mode adapters as active containment.
