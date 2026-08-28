# MSAA Data Governance and Privacy Framework

MSAA classifies information before access, storage, export, sharing, or AI processing. Unknown data types fail closed. The implementation is in `mac_audit_agent/data_governance.py` and aligns operationally with NIST Privacy Framework Identify-P, Govern-P, Control-P, Communicate-P, and Protect-P, plus NIST SP 800-53 AC-3, AC-6, AU-9, MP-4, SC-28, and SI-12.

## Default classifications

| Data | Class | Purpose | Default retention | Minimum role |
|---|---|---|---:|---|
| Public documentation | Public | User guidance | Indefinite | Viewer |
| Security finding | Internal | Explain detected conditions | 365 days | Viewer |
| Process metadata | Sensitive | Detection and investigation | 30 days | Security analyst |
| Security event | Sensitive | Detection and audit | 90 days | Security analyst |
| Report | Sensitive | Analyst-reviewed reporting | 365 days | Auditor |
| Forensic evidence | Restricted | Incident investigation | Organization-defined | Security analyst |
| Access audit | Restricted | Accountability | 730 days | Auditor |

Retention values are defaults, not legal advice. Invalid or missing timestamps are retained for review. The engine identifies eligible records but does not delete them; an authorized system-specific workflow must preserve holds, chain of custody, and deletion evidence.

## Fail-closed controls

- Unclassified data is denied.
- Restricted and sensitive exports require an explicit destination, approval, suitable role, and verified protection evidence.
- Permissions are not represented as encryption. A caller must supply evidence that encryption at rest or secure transport was verified.
- External sharing and external AI processing are disabled for operational data by default.
- Recursive sanitization removes common secrets and identity/location metadata before approved processing. Findings contain secret type and location only, never the matched value.
- Every allow and deny decision is written to a SHA-256 linked audit chain.

## Roles

Viewer < Auditor < Security Analyst < Administrator. Authentication must be time-limited and name its authorization source. Role checks do not grant macOS privileges and do not bypass operating-system access controls.

## Collection review

Every new collector must document its data type, purpose, storage location, retention, minimum role, export behavior, and protection requirements. Run a privacy impact assessment before enabling personal content, restricted evidence, external transfer, community sharing, or external AI processing. Passwords, tokens, credentials, private keys, and unrelated personal content are prohibited.

## Known boundary

This framework makes and audits governance decisions. It does not claim that a volume is encrypted, a transport is secure, or a key is protected without evidence from the relevant platform control. Deployments must configure encryption, key management, backup, legal holds, and retention to organizational requirements.
