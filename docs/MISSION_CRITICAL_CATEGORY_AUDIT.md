# MSAA mission-critical category audit

Status is based on repository source and tests, not marketing intent. `Implemented` means a substantial local capability exists; it does not imply production qualification. `Partial` means important acceptance requirements remain. `Externally blocked` means repository code cannot supply the required entitlement, signing identity, privacy approval, feed credentials, managed infrastructure, or hardware validation.

| # | Category | Status | Existing architecture | Material gaps / blockers |
|---|---|---|---|---|
| 1 | Security Configuration Baseline | Implemented, integration partial | `security_controls`, `baseline_drift`, settings reconciliation, firewall/network baselines, recovery snapshots | Dedicated consolidated dashboard and approved organization-policy workflow remain incomplete. |
| 2 | EDR Telemetry | Partial; externally blocked for production parity | process explorer, native event bridge, network timeline, file monitoring, anti-ransomware native sensor source | Apple Endpoint Security entitlement, signed sensor, Full Disk Access, live sequence/deadline qualification, and Intel/Apple Silicon host validation are required. |
| 3 | MITRE Coverage Matrix | Partial | framework mapping engine, persistence/ransomware mappings, report framework summaries | A dedicated coverage dashboard and negative/partial coverage claims need one canonical evidence matrix. |
| 4 | Sigma Engine | Missing | Existing proprietary/ransomware rule packages provide adjacent validation patterns | Sigma parser, restricted-field schema, aggregation semantics, rule signing/versioning, and fixtures require a separate reviewed design. |
| 5 | YARA Hunting | Partial | bounded optional YARA backend plus exact SHA-256 indicators | General scan orchestration, signed rule packages, scheduling, evidence/report/GUI integration, and performance qualification remain. |
| 6 | Threat Intelligence | Partial | CISA KEV/NVD enrichment, Apple exposure sources, consent-gated registry providers | MISP/OpenCTI/STIX/TAXII and commercial/abuse feeds require credentials, privacy policy, freshness, provenance, and rate-limit handling. |
| 7 | SIEM Integration | Missing | JSON/HTML/CSV and structured database events exist | Authenticated syslog/CEF, vendor schemas, buffering/retry, delivery receipts, redaction policy, TLS identity, and STIX/TAXII export are not implemented. |
| 8 | Hardware Security Trust | Partial | system-integrity review, Secure Boot/reduced-security posture, hardware inventory and change monitoring | Secure Enclave attestation and DFU/recovery provenance are limited by public macOS APIs and require hardware/UAT evidence. |
| 9 | DLP | Missing by design pending privacy policy | secret redaction and ClickFix clipboard classification are narrow adjacent controls | Broad sensitive-data discovery requires explicit scope, authorization, minimization, exclusions, retention, and legal/privacy review. |
| 10 | Application Control | Partial | Not Signed inventory, trust store, signature/notarization assessment, firewall/application controls | Enforcement policy, signed privileged boundary, allowlist deployment, rollback, and false-positive qualification remain. No automatic block claim is appropriate. |
| 11 | macOS Privacy Security | Implemented, attribution partial | privacy monitor, TCC metadata, keylogger detection, security-control monitor | Full Disk Access affects visibility; authoritative process attribution needs Endpoint Security/native telemetry. MSAA must never edit TCC databases. |
| 12 | Secure Software Development Assurance | Implemented, release qualification partial | integrity manifests, signing, provenance, release gates, dependency constraints, code review, SSDF documentation | Production signing/notarization credentials, clean-host builds, and independent release review remain external. |
| 13 | SBOM Generation | Partial | release CycloneDX generation and local multi-ecosystem manifest parsing | Endpoint-wide SPDX/CycloneDX inventory, component hashes/licenses, merge/deduplication, and GUI/report integration remain. |
| 14 | Cryptographic Security | Partial | certificate trust inventory, TLS/certificate findings, code-review weak-digest rules, signing verification | Unified crypto inventory, policy/version handling, trust-chain validation, and PQC readiness remain. |
| 15 | SOAR | Partial | emergency response state machine, ransomware containment orchestration, evidence-first adapters, alert action queues | Signed privileged adapters and enterprise playbook authorization/audit integrations remain. Source mode must stay inert. |
| 16 | User Awareness | Partial | education models, ClickFix detection and safe simulation foundation, attack validation mode | Phishing/ransomware exercise content, authorization workflow, metrics, accessibility UAT, and non-production event isolation need expansion. |
| 17 | Asset Management | Partial | hardware/users/software collectors, Not Signed inventory, network identity, assessment history | Canonical asset identity, lifecycle/reconciliation, MDM import, ownership, and fleet database remain. |
| 18 | Configuration Drift | Implemented | general baseline drift, persistence baselines, network baselines, settings versioning | Centralized dashboard and organization exception/approval workflow remain incomplete. |
| 19 | Behavioral Analytics | Partial | ransomware multi-window behavior, network drift, investigation priority, process risk, baseline analytics | General historical feature store, poisoning resistance, privacy policy, seasonality, and explainable rare-event calibration remain. |
| 20 | Security Control Database | Implemented in this change; integration partial | `security_control_database` aggregates control monitoring, framework inference, command mappings, remediation, and evidence requirements | GUI consumers and all detector/report adapters still need migration to the canonical query surface. |

## Architectural conflicts

- EDR, process containment, and authoritative file-access attribution cannot be honestly completed by Python filesystem polling. The approved architecture requires a minimal signed Endpoint Security component.
- SIEM, threat-intelligence, and registry integrations require explicit destination authorization, redaction, TLS identity, delivery auditing, and offline failure behavior. A generic HTTP client is not sufficient.
- DLP is high privacy risk. No broad content scanner should be added until scope, consent, retention, exclusions, and handling policy are approved.
- Application control cannot share the GUI process privilege boundary. Enforcement requires signed privileged components, exact identity checks, rollback, and durable policy.
- Existing framework mappings are supporting context. They must not be converted into certification or occurrence claims.

## Recommended implementation order

1. Migrate reports and new modules to the canonical Security Control Database and add mapping-conformance tests.
2. Build the MITRE coverage matrix from tested detector evidence and explicit limitations.
3. Add SIEM export as a local, redacted, delivery-audited spool before any network transport.
4. Extend signed rule-package infrastructure for Sigma; do not execute arbitrary conversion code.
5. Generalize bounded YARA orchestration using signed rules and evidence-first reporting.
6. Complete SBOM merge/export and asset identity before broader fleet or supply-chain claims.
7. Defer DLP and enforcement until privacy and privileged-boundary designs are approved.
