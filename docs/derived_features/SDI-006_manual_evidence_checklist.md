# SDI-006: Manual Evidence Checklist

## Source Observation Summary

The requested adjacent source was missing. This feature is derived from assessment procedures that require human and organizational evidence.

## Why MSAA Needs It

Local technical scans cannot satisfy policy, training, scope, or procedure requirements by themselves.

## Official Standard Mapping

- `nist_sp_800_171a`
- `cmmc_dodcio_resources`
- `pci_dss_roc_aoc_templates`

Mapping confidence: `manual_review_required`.

## Original MSAA Design

Add a checklist generator for policies, procedures, training records, IR plan, SSP, POA&M, asset inventory, access authorization records, and scope documentation.

## Data Model

Fields: `requirement_id`, `evidence_needed`, `suggested_document_name`, `owner`, `status`, `notes`, `linked_local_evidence`.

## Collector Behavior

No automated collection of private documents. Users may record status and notes.

## UI Behavior

Framework Readiness adds a Manual Evidence tab.

## Report Behavior

Word and Excel reports include manual evidence checklist sections.

## Evidence Behavior

Manual evidence remains separate from local technical evidence.

## Limitations

MSAA does not certify, attest, or approve organizational evidence.

## Manual Evidence Checklist

This feature is itself the checklist source and should seed common evidence categories.

## Test Plan

- Checklist rows are not marked collected automatically.
- Exports include status and notes.
- False-claim scanner remains clean.

## Non-Copying Statement

Checklist wording must be MSAA-authored and based on official assessment categories, not another project’s report text.
