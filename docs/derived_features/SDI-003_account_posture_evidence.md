# SDI-003: Account Posture Evidence

## Source Observation Summary

No adjacent source was available. This feature is derived from access-control and identity-readiness requirements.

## Why MSAA Needs It

Account data appears in scan output, but analysts need a control-family summary for least privilege and account lifecycle review.

## Official Standard Mapping

- `nist_sp_800_53_r5`
- `nist_sp_800_171_r3`
- `cisa_cpg_2_0`
- `cmmc_dodcio_resources`

Mapping confidence: `partial`.

## Original MSAA Design

Create a redacted Account Posture Evidence section summarizing local administrators, guest status, stale users, sudoers exposure, SSH configuration, and login posture where observable.

## Data Model

Fields: `account_signal`, `risk_summary`, `evidence_status`, `redaction_applied`, `manual_review_required`, `source_ids`.

## Collector Behavior

Collect read-only summaries and redact sensitive account values where feasible.

## UI Behavior

Framework Readiness displays Account and Access Control evidence with review guidance.

## Report Behavior

Reports include least-privilege support evidence and manual evidence gaps.

## Evidence Behavior

MSAA supplies local technical evidence. Authorization records and identity governance evidence remain manual.

## Limitations

MSAA cannot verify cloud identity, MFA, HR joiner/mover/leaver workflows, or contractual access approvals.

## Manual Evidence Checklist

- Access authorization records
- Account review cadence
- MFA/SSO policy
- Privileged access approvals

## Test Plan

- Account summaries avoid raw sensitive dumps.
- Mapping confidence is partial.
- Manual review requirements remain visible.

## Non-Copying Statement

Collectors, UI wording, and reports must be MSAA-native and not cloned from another tool.
