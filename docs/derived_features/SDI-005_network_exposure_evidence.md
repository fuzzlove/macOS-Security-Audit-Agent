# SDI-005: Network Exposure Evidence

## Source Observation Summary

No adjacent project capability could be inspected. This idea is based on network and communications protection readiness requirements.

## Why MSAA Needs It

Network Intelligence should present local exposure evidence in a framework-ready matrix.

## Official Standard Mapping

- `nist_sp_800_53_r5`
- `cisa_cpg_2_0`
- `pci_dss_4_0_1`
- `nist_csf_2_0`

Mapping confidence: `supporting_evidence`.

## Original MSAA Design

Create Network Exposure Evidence rows for listeners, DNS, gateway, VPN/proxy, firewall, localhost services, and suspicious remote endpoint indicators.

## Data Model

Fields: `network_signal`, `observed_state`, `exposure_summary`, `evidence_status`, `scope_note`, `source_ids`, `limitations`.

## Collector Behavior

Use local read-only collectors. External scanning remains disabled unless explicitly enabled by the user.

## UI Behavior

Network Intelligence shows standards evidence rows alongside diagnostics.

## Report Behavior

Reports include network exposure evidence, limitations, and manual scope requirements.

## Evidence Behavior

Local evidence supports endpoint visibility. Architecture and PCI scope remain manual evidence.

## Limitations

MSAA cannot determine network boundary or cardholder-data environment scope alone.

## Manual Evidence Checklist

- Network architecture
- Segmentation scope
- Firewall policy
- PCI scope statement if applicable

## Test Plan

- No unauthorized external scan runs by default.
- Evidence rows include limitations.
- PCI is labeled as industry readiness only.

## Non-Copying Statement

Network parsing, UI copy, and report output must be original MSAA implementation.
