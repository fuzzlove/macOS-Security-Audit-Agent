# Security Regression Detection

Security Regression Detection consumes integrity-bound Continuous Security Assurance snapshots and detailed evidence from Software Attestation, Identity Attack Detection, Threat Exposure Management, Security Control Validation, persistence findings, and the Security Posture Graph. It does not collect duplicate telemetry or change endpoint state.

Only a current-state record with an evidence reference can produce a change. Each change preserves the previous and current values, actor, responsible process, reason, source, authorization state, policy state, timestamp, and supporting evidence. Missing attribution is displayed as unknown rather than inferred.

Changes are classified as `security_improvement`, `neutral_change`, or `security_regression`. Approved administrative changes remain visible. Approval may qualify a genuinely neutral update, but it does not make a policy violation or security-control loss safe. Scores identify the category weight, severity, asset importance, and threat-intelligence multiplier used.

Snapshots, assessments, and durable history use SHA-256 integrity verification. Emergency-response output is recommendation-only and requires authorization. No software deletion, configuration modification, containment, or autonomous remediation is implemented.

Framework mapping includes NIST SP 800-53 CM-3, CM-5, CM-6, SI-4, CA-7, and AU-6; NIST CSF 2.0 asset, platform security, monitoring, response-analysis, and governance outcomes; and relevant CIS Apple macOS configuration controls.
