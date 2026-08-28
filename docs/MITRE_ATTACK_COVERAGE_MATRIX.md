# MITRE ATT&CK Coverage Matrix

MSAA reports ATT&CK framework relevance separately from detection coverage. A finding may map to a technique without proving that MSAA has complete detection coverage for that technique.

Coverage statuses are:

- `implemented`: a detector, evidence contract, and validation references exist, with no recorded material coverage limitation.
- `partial`: useful detection exists, but telemetry, attribution, advisory, or deployment limitations remain.
- `unavailable`: MSAA does not claim coverage, including where collection would conflict with privacy or product boundaries.
- `not_assessed`: related data may exist, but the technique-level detection has not been qualified.

Positive coverage claims must identify detector IDs, evidence sources, and validation tests. Reports expose observed technique mappings separately, and observations never promote a status. The canonical source is `mac_audit_agent/mitre_coverage.py`; JSON and HTML scan reports consume the same matrix.

This matrix supports detection engineering review. It is not certification, an authorization decision, or proof that a technique occurred on an endpoint.

The Scan Categories page also includes `ATT&CK Discovery Exposure` checks for system/build information, host identity, logged-on users, current account groups, mounted shares, security/management extensions, and the presence of common cloud/orchestration configuration directories. These commands are read-only and bounded. They show what metadata a local process could learn; an observable result is not automatically a vulnerability and does not prove an ATT&CK technique occurred. Credential and configuration file contents are deliberately excluded.
