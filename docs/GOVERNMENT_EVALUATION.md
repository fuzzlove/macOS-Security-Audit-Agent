# Government / Enterprise Evaluation

## Purpose

This document is intended to help security teams evaluate whether Mac Audit Agent is appropriate for institutional deployment.

## Scope

The tool is for local macOS audit, monitoring, and investigation work. It is not an offensive tool and does not claim to detect or remove all threats.

## Privacy Model

- local-only storage by default
- no telemetry
- no hidden network services
- no browser history or keychain inspection
- exports are user-controlled

## Deployment Modes

- user LaunchAgent
- system LaunchDaemon

## Data Stored

- findings
- monitor events
- reports
- notes
- review decisions
- evidence snapshots
- Apple Exposure Assessment cache
- deployment and health status

## Logs Generated

- scan logs
- monitor logs
- deployment audit logs
- notification decisions
- health report summaries

## Limitations

- the tool does not prove compromise
- the tool does not collect packet contents by default
- some detector classes may be noisy depending on endpoint configuration
- some macOS privacy-sensitive signals are limited to what the OS exposes locally

## Security Assumptions

- the local administrator is trusted
- the host filesystem is not already fully controlled by an attacker
- the user can review and interpret evidence

## Operational Risks

- noisy alerts can cause alert fatigue if misconfigured
- cleanup actions can destroy evidence if used at the wrong time
- stale deployment state can create false confidence

## Evidence Preservation

Before cleanup or remediation, preserve:

- logs
- notes
- reports
- snapshots
- the monitor database
