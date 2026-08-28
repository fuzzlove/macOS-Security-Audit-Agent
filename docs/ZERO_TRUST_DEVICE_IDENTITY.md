# Zero Trust Device Identity

The Zero Trust Device Identity module converts a current Continuous Security Assurance snapshot into a privacy-preserving internal attestation, transparent policy recommendations, and an auditable trust-state decision.

## Privacy and identity

MSAA does not autonomously collect a serial number or platform UUID for this module. A caller supplies either an administrator-approved device ID or an approved stable identifier plus an organization-specific secret of at least 16 bytes. The stable identifier is converted to an organization-scoped HMAC pseudonym; the raw value is not stored in the profile, attestation, or device-identity table.

Changing the organization secret produces a different device ID. This prevents the MSAA identifier from acting as a universal cross-organization tracking value.

## Trust states

- `TRUSTED`: at least 90% current evidence coverage, posture score at least 90, identity metadata available, and no policy-relevant concerns.
- `CONDITIONAL TRUST`: reviewable software, exposure, or evidence limitations that do not meet restricted criteria.
- `RESTRICTED TRUST`: active threat evidence, a critical known-exploited vulnerability, a disabled core protection, or another critical posture concern.
- `UNTRUSTED`: an authoritative integrity failure, confirmed compromise indicator, or unauthorized identity change.

These states are decision support. MSAA does not grant or deny access, lock users out, modify accounts, or initiate containment automatically.

## Attestation and audit

An attestation contains the pseudonymous device profile, CSAE scores, evidence coverage, domain statuses, reasons, evidence references, and policy results. SHA-256 detects stored attestation changes; this is not hardware-backed Apple attestation and is labeled accordingly.

The `device_identity` and `trust_decisions` tables preserve current identity state and decision history. Emergency Response integration only reports eligibility, evidence references, and an authorization-required workflow.

Native telemetry completeness, MDM enforcement, actual access decisions, organizational policy approval, and hardware-backed signing remain external deployment responsibilities.
