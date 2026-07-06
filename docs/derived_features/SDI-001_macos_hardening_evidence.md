# SDI-001: macOS Hardening Evidence

## Source Observation Summary

The requested adjacent `../macos_security` project was not available. This feature is derived from standards-requested comparison categories for macOS hardening.

## Why MSAA Needs It

MSAA already collects security posture data, but users need one readiness-oriented view for baseline hardening evidence.

## Official Standard Mapping

- `nist_csf_2_0`
- `nist_sp_800_53_r5`
- `cisa_cpg_2_0`
- `nsa_cybersecurity`
- `cmmc_dodcio_resources`

Mapping confidence: `supporting_evidence`.

## Original MSAA Design

Create an MSAA-native hardening evidence model that summarizes FileVault, firewall, Gatekeeper, SIP, Secure Boot, software update, sharing services, AirDrop, remote access, and profile posture.

## Data Model

Fields: `check_id`, `setting_name`, `observed_state`, `evidence_status`, `source_collector`, `last_checked`, `mapping_confidence`, `limitations`.

## Collector Behavior

Collectors are read-only, local-only, and summarize results instead of dumping raw command output.

## UI Behavior

Framework Readiness shows a Hardening Evidence section with status, source, and “What to review next” guidance.

## Report Behavior

Reports include hardening rows, limitations, source IDs, and manual evidence gaps.

## Evidence Behavior

Local evidence is marked collected, partial, stale, or unavailable. Organizational exceptions remain manual evidence.

## Limitations

MSAA cannot confirm organizational policy approval or contractual scope.

## Manual Evidence Checklist

- Approved secure configuration baseline
- Documented exceptions
- MDM/profile policy records
- Change approval records

## Test Plan

- Collector output includes evidence status and source IDs.
- Reports include limitations.
- False-claim scan prevents certification wording.

## Non-Copying Statement

This feature must be independently implemented in MSAA style and must not copy external code, command wrappers, UI text, report prose, or assets.
