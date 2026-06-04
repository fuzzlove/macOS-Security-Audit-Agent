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
