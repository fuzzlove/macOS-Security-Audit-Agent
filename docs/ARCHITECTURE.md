# Architecture

## Overview

Mac Audit Agent is a local-first macOS security platform with three major layers:

1. collectors and detectors
2. storage and correlation
3. analyst UI and export/reporting

## Core Data Flow

- Collectors gather read-only evidence
- Models normalize findings and events
- SQLite stores the local history
- Correlation engines group related activity
- UI panels present findings, priorities, and evidence
- Reports export the same local data model

## Deployment Modes

### User LaunchAgent

- Runs in the logged-in GUI session
- Best for visible alerts and user-facing notifications
- Suitable for desktop deployments where login-session visibility matters

### System LaunchDaemon

- Runs at boot
- Uses the shared system database
- Best for boot-time monitoring and persistent evidence capture
- Does not present GUI directly

## Separation of Concerns

- Monitor logic does not own the UI
- UI does not depend on private browser state
- Reporting does not mutate evidence
- Cleanup is separated from incident response

## Trust Boundaries

- Local machine vs exported artifacts
- User agent vs system daemon
- Read-only collection vs optional remediation
- Evidence storage vs presentation

## Native Assurance Foundation

`native/MSAAAssurance` is a macOS 14+ Swift package with separate core, UI,
verifier, and test targets. The unprivileged SwiftUI process consumes evaluated
results; it is not a collector or signing authority. The core owns strict policy
decoding, collector protocols, canonical evidence, deterministic evaluation,
logical append-only persistence, signing abstractions, and export. The standalone
verifier requires only the bundle and public key.

Evidence flows collector -> allowlisted normalization -> chained observation ->
deterministic evaluator -> signed checkpoint/manifest -> explicit export. Missing
or unhealthy collectors downgrade dependent controls. Simulated Endpoint Security
events remain labeled simulated. A future entitled system extension belongs across
an authenticated, versioned IPC boundary and must not contain UI, export, or policy
evaluation logic. Future MDM adapters provide claimed configuration as one evidence
source, not proof of operation. A future OSCAL exporter must validate against an
official schema before using the OSCAL label.

The JSONL store uses atomic whole-file replacement for this initial bounded
foundation. It is tamper-evident, not immutable. There is no automatic retention
or silent deletion. Production growth requires a transactional indexed store and
signed retention-boundary events.
