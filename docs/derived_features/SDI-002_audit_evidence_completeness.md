# SDI-002: Audit Evidence Completeness

## Source Observation Summary

The requested adjacent comparison source was missing. This idea comes from NIST/CMMC audit and accountability readiness needs.

## Why MSAA Needs It

MSAA has event, alert, integrity, and export evidence, but users need a single score explaining whether audit evidence is complete enough for review.

## Official Standard Mapping

- `nist_sp_800_53_r5`
- `nist_sp_800_171_r3`
- `cmmc_dodcio_resources`
- `nist_csf_2_0`

Mapping confidence: `direct`.

## Original MSAA Design

Add an Audit Evidence Completeness scorer that evaluates event DB writes, AlertDeliveryTrace, notifier heartbeat, export evidence, integrity history, and evidence snapshot availability.

## Data Model

Fields: `audit_area`, `required_evidence`, `current_status`, `last_seen`, `gap_reason`, `recommended_fix`, `source_id`.

## Collector Behavior

Use existing MSAA audit tables and logs. Do not read unrelated user files.

## UI Behavior

Evidence Matrix shows Audit Completeness with pass, partial, missing, or stale status.

## Report Behavior

Reports show coverage, gaps, and recommended next steps.

## Evidence Behavior

Technical evidence is collected locally. Log retention and review cadence are manual evidence.

## Limitations

MSAA cannot prove human review occurred unless the user attaches or records manual evidence.

## Manual Evidence Checklist

- Log review procedure
- Retention policy
- Reviewer assignment records
- Incident escalation records

## Test Plan

- Missing trace produces a gap.
- Fresh trace produces collected evidence.
- Manual evidence is not marked collected automatically.

## Non-Copying Statement

The scoring rules must be original MSAA logic over MSAA’s own evidence tables.
