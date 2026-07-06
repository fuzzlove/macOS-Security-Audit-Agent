# macos_security-Derived Implementation Plan

Generated: 2026-07-06

## Source Status

The requested adjacent project `../macos_security` was not available. This plan is therefore standards-derived and MSAA-original. No code, assets, templates, tests, or wording were copied from another project.

## Top 10 Recommended MSAA Improvements

### 1. macOS Hardening Evidence Panel

- Rationale: improves secure configuration visibility.
- Source observation: no adjacent source available; derived from public hardening/readiness expectations.
- Standards alignment: NIST CSF 2.0 PR/DE functions, NIST SP 800-53 CM/SI/AC, CISA CPG, NSA public guidance.
- Original implementation: `mac_audit_agent/hardening/` collectors and a Framework Readiness evidence summary.
- UI impact: new hardening evidence table.
- Report impact: hardening section in HTML/Word/Excel/JSON.
- Tests: collector empty-state, no raw dumps, source mapping.
- Priority: high.
- Non-copying assurance: implement with MSAA-native models and wording.

### 2. Audit Evidence Completeness Score

- Rationale: strengthens auditability and alert traceability.
- Source observation: no adjacent source available.
- Standards alignment: NIST AU family, CMMC audit readiness, CSF Detect.
- Original implementation: compute completeness from event DB, alert traces, report history, and integrity history.
- UI impact: Operational Health and Evidence Matrix score.
- Report impact: audit evidence completeness row.
- Tests: missing traces reduce score; no raw logs in help/report body.
- Priority: high.
- Non-copying assurance: uses existing MSAA event and trace schema.

### 3. Account Posture Evidence

- Rationale: supports least privilege and account lifecycle review.
- Source observation: no adjacent source available.
- Standards alignment: NIST AC/IA, CMMC AC/IA, CISA CPG.
- Original implementation: summarized local account/admin/sudoers/SSH posture.
- UI impact: Account and Access Control readiness section.
- Report impact: evidence and manual review split.
- Tests: redaction, no sensitive dumps, manual evidence rows.
- Priority: high.
- Non-copying assurance: no copied parsers or report language.

### 4. Persistence Coverage Summary

- Rationale: improves persistence and configuration-change visibility.
- Source observation: no adjacent source available.
- Standards alignment: NIST SI/CM, MITRE ATT&CK, CMMC SI/CM.
- Original implementation: MSAA-native coverage matrix over existing Persistence Intelligence.
- UI impact: coverage row in Persistence Intelligence.
- Report impact: mapped evidence and gaps.
- Tests: every persistence source has collected/unavailable status.
- Priority: high.
- Non-copying assurance: build on existing MSAA collectors.

### 5. Network Exposure Evidence Matrix

- Rationale: improves communications protection and local exposure review.
- Source observation: no adjacent source available.
- Standards alignment: NIST SC, CISA CPG, PCI DSS Req. 1 where applicable.
- Original implementation: summarize listeners, DNS, gateway, VPN/proxy, firewall, localhost services.
- UI impact: Network Intelligence standards panel.
- Report impact: Network Evidence Matrix rows.
- Tests: no external scanning unless explicitly enabled.
- Priority: medium.
- Non-copying assurance: no copied scan profiles.

### 6. Manual Evidence Checklist

- Rationale: separates local technical evidence from policy/process evidence.
- Source observation: no adjacent source available.
- Standards alignment: NIST 800-171A, CMMC assessment guidance, PCI reference templates.
- Original implementation: checklist model with owner/status/notes/evidence_needed.
- UI impact: Evidence Matrix and POA&M subtab.
- Report impact: Word/Excel/JSON checklist.
- Tests: policy controls are not auto-met by scans.
- Priority: high.
- Non-copying assurance: MSAA-native checklist wording.

### 7. Apple Exposure Freshness Mapping

- Rationale: strengthens vulnerability/update visibility.
- Source observation: no adjacent source available.
- Standards alignment: CISA KEV, NIST SI/RA, CMMC SI/RA.
- Original implementation: map existing Apple Exposure metadata to framework evidence rows.
- UI impact: freshness state in Framework Readiness.
- Report impact: vulnerability evidence freshness.
- Tests: stale/cache/failed states remain explicit.
- Priority: medium.
- Non-copying assurance: build on MSAA Apple Exposure implementation.

### 8. Removable Media Evidence Rows

- Rationale: supports media protection and physical device awareness.
- Source observation: no adjacent source available.
- Standards alignment: NIST MP/PE, CMMC MP/PE, PCI device awareness where relevant.
- Original implementation: map existing physical_devices and hardware artifacts.
- UI impact: Physical Devices evidence detail.
- Report impact: removable media readiness rows.
- Tests: unavailable status still emits structured evidence.
- Priority: medium.
- Non-copying assurance: no copied device inventory code.

### 9. Integrity Drift Evidence Summary

- Rationale: supports configuration and system integrity monitoring.
- Source observation: no adjacent source available.
- Standards alignment: NIST CM/SI, CMMC CM/SI.
- Original implementation: summarize strict verifier diffs, authorization records, and evidence snapshots.
- UI impact: Integrity & Trust standards row.
- Report impact: change authorization evidence summary.
- Tests: authorized changes are still shown.
- Priority: high.
- Non-copying assurance: use existing strict verifier.

### 10. Standards Language Guardrail

- Rationale: prevents unsupported framework and endorsement claims.
- Source observation: no adjacent source available.
- Standards alignment: cross-framework attribution and assessor-scope guardrail.
- Original implementation: Pre-UAT scan across UI, reports, docs, and exports.
- UI impact: Pre-UAT/Framework Readiness check.
- Report impact: explicit pass/fail guardrail.
- Tests: forbidden claims fail.
- Priority: high.
- Non-copying assurance: purely MSAA-original safety control.

## Implementation Rule

Implement only high-value, standards-backed, low-risk improvements that fit MSAA's defensive, local-first scope. Do not implement a candidate if it requires copying another project's code, text, templates, or assets.
