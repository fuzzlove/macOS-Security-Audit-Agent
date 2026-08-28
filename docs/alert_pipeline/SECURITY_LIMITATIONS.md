# Security limitations

- Notification deduplication cannot guarantee detector correctness.
- Local tamper evidence is limited against fully privileged, kernel-level, or hardware-level attackers.
- Storage exhaustion may require controlled, explicitly marked compaction.
- Alignment with NIST, DoD RMF, DISA guidance, CIS, CISA, or MITRE does not constitute certification, approval, STIG compliance, or authorization.
- Automated response can create operational risk and requires policy authorization.
- Suppression rules can create blind spots when misconfigured.
- Unknown future threats require new detectors or policies.
- The endpoint-local pipeline does not replace centralized protected log collection.
