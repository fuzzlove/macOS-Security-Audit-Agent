# ADR-006: Privilege Boundaries

Status: Accepted

## Context
Monitoring and Endpoint Security require privileges that the GUI must not inherit.

## Decision
Keep GUI/CLI unprivileged; use explicit headless installation, system daemon, signed sensor, user notifier, and narrowly scoped helper roles.

## Alternatives considered
Running the GUI as root and direct TCC/SIP changes were rejected.

## Security consequences
Local authorization, identity validation, evidence preservation, and safe containment remain mandatory.

## Operational consequences
Administrator/MDM approval and Apple entitlements remain deployment gates.

## Migration consequences
Launchd identifiers and data remain compatible; installers resolve executable paths at install time.
