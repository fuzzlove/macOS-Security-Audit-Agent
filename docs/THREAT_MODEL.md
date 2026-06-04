# Threat Model

## What This Tool Defends Against

- accidental exposure of local services
- unexpected persistence changes
- suspicious process execution
- unauthorized or unexpected use after idle periods
- visibility gaps in the monitor itself
- evidence loss through premature cleanup

## What It Does Not Attempt

- no retaliation
- no exploitation
- no credential theft
- no hidden persistence
- no stealthy self-repair
- no browser history inspection
- no malware removal claims

## Primary Assets

- local findings database
- monitor event history
- investigation notes
- exported reports
- evidence snapshots
- Apple Security Forecast cache

## Adversary/Failure Classes

- unintentional operator error
- overactive or broken detectors
- user-session blind spots
- local malware or tampering
- broken deployment state
- stale database or runtime mismatches

## Security Goals

- preserve evidence
- reduce false confidence
- avoid popup storms
- keep all state local
- make alerts explainable
