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
- Apple Exposure Assessment cache

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

## Assurance Evidence Threats

- Alteration, deletion, replay, duplication, or reordering of local records is
  detected by sequence numbers, previous-record digests, and canonical digests.
- Export alteration is detected by manifest file digests and a signed manifest
  checkpoint. Stale evidence is reported as stale, never current.
- Collector outage, permission loss, expired heartbeat, dropped events, and
  sequence gaps prevent dependent controls from passing.
- Policy alteration and unsigned production imports are rejected. Explicit
  development imports remain visibly unverified in evidence and UI.
- Imported metadata is size bounded and strictly decoded. Command output is
  bounded, allowlisted, and not logged raw, reducing parser and log-injection risk.
- Signing-key compromise can permit convincing future signatures; rotation,
  revocation, external timestamping, and protected-key operational procedures are
  required production controls.
- Privileged collectors are a separate trust boundary. Their compromise can falsify
  source telemetry, so cross-source corroboration and signed heartbeats are future
  work. Application downgrade must be detected by policy/application versions.
- Excessive collection is limited by typed metadata: no document bodies, browsing,
  clipboard, keystrokes, credentials, tokens, or environment dumps.
- Synthetic evidence is explicitly labeled and cannot satisfy production pass.

This model does not claim protection against a fully compromised kernel, firmware,
Secure Enclave, signing authority, or an attacker controlling every evidence source.
