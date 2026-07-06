# SDI-010: Readiness Language Guardrail

## Source Observation Summary

No adjacent source was reviewed. This guardrail is derived from the need to avoid unsupported certification, compliance, or endorsement claims.

## Why MSAA Needs It

MSAA maps evidence to standards but must not imply official assessment authority, approval, certification, or endorsement.

## Official Standard Mapping

- `nist_csf_2_0`
- `cisa_cpg_2_0`
- `cmmc_dodcio_resources`
- `nsa_cybersecurity`
- `pci_dss_4_0_1`
- `mitre_attack_enterprise`

Mapping confidence: `direct`.

## Original MSAA Design

Add a scan that checks UI-facing source, docs, reports, exports, About, Support, and Framework Readiness content for unsupported claims.

## Data Model

Fields: `phrase`, `path`, `context`, `severity`, `recommended_replacement`.

## Collector Behavior

Static text scan only. It does not alter files automatically.

## UI Behavior

Developer diagnostics shows pass/fail state and remediation guidance.

## Report Behavior

Pre-UAT reports include a standards false-claim result.

## Evidence Behavior

Findings are evidence of wording risk, not security findings.

## Limitations

Legal review may still be required for public release materials.

## Manual Evidence Checklist

- Public release wording review
- Standards attribution review
- Legal/assessor review where needed

## Test Plan

- Forbidden phrases fail Pre-UAT.
- Allowed readiness/evidence-support wording passes.
- Tests skip only scanner implementation files and test fixtures.

## Non-Copying Statement

This guardrail protects MSAA’s independent language and prevents unsupported external-source claims.
