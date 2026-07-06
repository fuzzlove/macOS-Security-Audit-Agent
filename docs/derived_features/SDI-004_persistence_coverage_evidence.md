# SDI-004: Persistence Coverage Evidence

## Source Observation Summary

The adjacent project was unavailable. The improvement is based on standards and MITRE ATT&CK macOS technique context.

## Why MSAA Needs It

Persistence Intelligence should explain covered persistence surfaces and known evidence limitations.

## Official Standard Mapping

- `nist_sp_800_53_r5`
- `nist_sp_800_171_r3`
- `cmmc_dodcio_resources`
- `mitre_attack_macos`

Mapping confidence: `supporting_evidence`.

## Original MSAA Design

Add a Persistence Coverage Evidence summary for LaunchAgents, LaunchDaemons, login items, cron/at, shell profiles, privileged helpers, profiles/MDM, and browser extensions.

## Data Model

Fields: `surface`, `collector_status`, `items_observed`, `risk_summary`, `mapping_confidence`, `manual_evidence_required`, `limitations`.

## Collector Behavior

Use MSAA’s existing persistence collectors and add coverage metadata. No copied detector logic.

## UI Behavior

Persistence Intelligence shows coverage and gaps before detailed findings.

## Report Behavior

Evidence Matrix includes persistence surfaces, evidence locations, and limitations.

## Evidence Behavior

Local evidence includes file metadata, ownership, signature/hash summaries, and provenance signals.

## Limitations

ATT&CK mapping is technique context, not proof of malicious behavior.

## Manual Evidence Checklist

- Approved software inventory
- Change tickets
- MDM deployment records
- Exception approvals

## Test Plan

- Each persistence surface has a coverage status.
- MITRE source IDs resolve.
- Partial coverage is not reported as complete.

## Non-Copying Statement

MSAA must independently implement coverage metadata and avoid copying external detectors or descriptions.
