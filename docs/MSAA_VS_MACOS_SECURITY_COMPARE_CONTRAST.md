# MSAA vs macos_security Compare / Contrast

Generated: 2026-07-06

## Source Availability

The requested adjacent project `../macos_security` was not found. Parent-directory fallback names were checked, including `macos_security`, `macOS_security`, `macos-security`, and `MacOS-Security`.

The only matching path discovered was `../macOS-Security-Audit-Agent/macos_security`, which is inside the current MSAA checkout. It was not used as a substitute comparative source.

## Comparison Matrix

| category | macos_security observed capability | MSAA current capability | overlap | gap | standards relevance | MSAA derivative opportunity | implementation priority | copy-risk level | approved_for_design | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macOS baseline hardening | Unavailable; adjacent source not found | Safe Scan, integrity verification, Apple Exposure, settings diagnostics | Unknown | Consolidated hardening posture can be clearer | NIST CSF PR.PS, NIST CM, CISA CPG, NSA public guidance | Add a read-only macOS Hardening Evidence view | High | Low | yes | Standards-backed and implementable from MSAA collectors |
| account and access control | Unavailable | User/account artifacts in scan output and reports | Unknown | Least-privilege evidence is not summarized by domain | NIST AC/IA, CMMC AC/IA, CISA CPG | Add Account Posture Evidence summary | High | Low | yes | Uses local MSAA evidence and manual-evidence separation |
| audit logging | Unavailable | Event DB, alert traces, audit logs, export history | Unknown | Audit completeness scoring can be stronger | NIST AU, CMMC AU, NIST CSF DE.CM | Add Audit Evidence Completeness score | High | Low | yes | Original scoring layer over existing MSAA audit data |
| local event monitoring | Unavailable | Persistent monitor, notifier, AlertDeliveryTrace | Unknown | Manual testing evidence exists but needs standards view | NIST AU/SI, CISA CPG | Map alert trace evidence into Evidence Matrix | Medium | Low | yes | Extends existing telemetry without external source dependency |
| persistence detection | Unavailable | Persistence Intelligence, LaunchAgents/Daemons, baseline drift | Unknown | Coverage summary can identify unsupported persistence areas | MITRE ATT&CK, NIST SI/CM, CMMC SI/CM | Add Persistence Coverage Evidence summary | Medium | Low | yes | Technique context comes from public ATT&CK references |
| network posture | Unavailable | Network Intelligence collectors and diagnostics | Unknown | Framework evidence mapping can be more explicit | NIST SC, CISA CPG, PCI DSS Req. 1 relevance | Add Network Exposure Evidence Matrix rows | Medium | Low | yes | Local-only, read-only endpoint evidence |
| endpoint integrity | Unavailable | Strict integrity verifier and signed manifest work | Unknown | Standards mapping and POA&M export can be deeper | NIST CM/SI, CMMC CM/SI | Add Integrity Drift Evidence Summary | High | Low | yes | Uses existing MSAA integrity data |
| vulnerability/update posture | Unavailable | Apple Exposure Assessment and freshness metadata | Unknown | Vulnerability readiness rows can cite source freshness | NIST RA/SI, CISA KEV, CMMC RA/SI | Add Exposure Freshness evidence row | Medium | Low | yes | Uses official vulnerability/source metadata |
| removable media / physical devices | Unavailable | Physical device artifacts and USB/Bluetooth monitoring | Unknown | Trusted/untrusted device model is not mature | NIST MP/PE, CMMC MP/PE, PCI device awareness | Add Media Protection Evidence summary | Medium | Low | yes | Read-only evidence with manual authorization records |
| incident response | Unavailable | Live response, evidence snapshots, reports | Unknown | Chain-of-custody and manual evidence checklist can be clearer | NIST IR, CMMC IR, CISA CPG | Add IR Evidence Package Checklist | High | Low | yes | MSAA-native workflow and documentation |
| evidence collection | Unavailable | Evidence snapshots, reports, framework readiness payloads | Unknown | Manual/process evidence needs stronger separation | NIST 800-171A, CMMC guides, PCI ROC/AOC references | Add Manual Evidence Checklist generator | High | Low | yes | Standards assessment procedures require manual evidence |
| reporting | Unavailable | HTML, JSON, Word, Excel exports | Unknown | Comparative summary and standards-derived gaps can be included | NIST/CMMC/CISA/PCI readiness support | Add Standards-Derived Improvements report section | Medium | Low | yes | Summary-only; no external code or prose |
| dashboard/UI | Unavailable | Framework Readiness and Support pages | Unknown | Comparative review should be visible without raw source snippets | NIST/CISA/DoD transparency expectations | Add Comparative Improvement Review diagnostics panel | Low | Low | yes | Shows MSAA action items only |
| configuration management | Unavailable | Settings reconciliation, baseline drift, integrity auth | Unknown | Configuration history can be tied to POA&M | NIST CM, CMMC CM | Add Configuration Change Evidence rows | Medium | Low | yes | Built from MSAA state and authorization records |
| framework mapping | Unavailable | CMMC/NIST readiness, source registry, POA&M | Unknown | Add CISA, NSA, PCI, MITRE registry coverage in one source model | NIST, CISA, DoD/CMMC, NSA, PCI, MITRE | Expand official source registry and mapping confidence | High | Low | yes | Official/public sources only |
| CMMC/NIST readiness | Unavailable | CMMC readiness data model and reports | Unknown | Manual evidence and mapping confidence need continuous checks | CMMC L1/L2/L3, NIST 800-171/171A | Add accepted-idea mapping validation | High | Low | yes | Pre-UAT-enforced guardrail |
| PCI DSS readiness | Unavailable | Source registry support only where relevant | Unknown | Payment-card scope must be manual | PCI DSS v4.0.1 | Add PCI relevance as optional industry readiness mapping | Low | Low | yes | Explicitly not a government framework |
| NSA/CISA/DoD guidance alignment | Unavailable | Source registry and acknowledgement disclaimer | Unknown | Source freshness and endorsement guardrails need enforcement | NSA/CISA/DoD public guidance | Add standards false-claim scanner coverage | High | Low | yes | Prevents unsupported endorsement wording |
| tests and release readiness | Unavailable | Pre-UAT, release checks, UI tests | Unknown | Comparative artifacts need regression checks | All mapped frameworks | Add Pre-UAT checks for docs, source registry, and mappings | High | Low | yes | Verifies process without copying |

## Non-Copying Summary

No adjacent project code, assets, UI text, reports, tests, schemas, or implementation patterns were available for review or copied. All approved opportunities above are derived from MSAA’s current gaps and official/public standards families.
