# Security Research Device

MSAA's Security Research Device workflow is an evidence-oriented macOS hardening assistant for lawful, explicitly authorized research. It does not turn a Mac into an Apple Security Research Device, grant access to Apple's Security Research Device Program, establish compliance, or confer government authorization or endorsement.

## Profiles

- **Theft Prevention** covers encryption, boot and system integrity, firewall, screen lock, account separation, and recovery.
- **Sensitive Security Research** adds updates, software provenance, sharing services, approved network/DNS/VPN scope, and data handling.
- **CISA / DoD Submission Readiness** adds incident, coordinated-disclosure, evidence-preservation, and authority-review tasks. The label describes intended preparation only.

Choose the smallest profile appropriate to the research and the system owner's written requirements. A profile cannot replace engagement authorization, data-classification instructions, export-control review, or a current platform-specific baseline.

## How the wizard works

The wizard presents one task at a time. `Run Read-Only Checks` asynchronously reuses MSAA's existing bounded collectors for FileVault, Secure Boot, System Integrity Protection, and the application firewall. Missing or unsupported telemetry remains **unknown**. Other tasks provide a manual checklist because MSAA cannot safely infer organizational approval, recovery effectiveness, network scope, or data-handling authority.

`Record Evidence Collected` creates a timestamped monitor event. It records the assessor's assertion; it does not convert a failed or unknown check to pass. The JSON export contains the selected profile, current task results, guidance, UTC export time, and a SHA-256 digest over the canonical assessment content.

## Applying changes safely

The first implementation is preview-first. It does not silently change security settings. Apply changes through macOS System Settings or an approved MDM workflow after reviewing dependencies, recovery, remote-management availability, and research-tool requirements. Administrator authentication must occur through the macOS or approved management interface; MSAA does not collect administrator passwords.

Reduced Security, disabled SIP, kernel/system extensions, remote administration, broad network access, and unusual software may sometimes be required in a specifically authorized laboratory. Treat each as a documented, time-limited exception with compensating controls—not as a passing default.

## Source and mapping policy

The workflow uses short mappings and does not bundle standards text. Administrators must validate current revisions before operational use:

- Apple Platform Security for FileVault, Secure Boot, the signed system volume, code signing, and system security behavior.
- NIST SP 800-53 and SP 800-171 identifiers for control traceability.
- The NIST macOS Security Compliance Project for open, versioned macOS baseline-generation resources.
- The current Apple macOS STIG from the DoD Cyber Exchange when a DoD baseline is contractually applicable.
- CISA guidance and the applicable vendor/coordinated-vulnerability-disclosure channel for incident and vulnerability submission preparation.
- INTERPOL cybercrime resources for reporting awareness and international coordination context only. INTERPOL does not define a macOS hardening baseline, grant private system access, or replace competent legal and system-owner authority.

## Limitations

- No configuration can guarantee prevention of intellectual-property theft or compromise.
- A passing point-in-time check can become stale immediately after a change.
- Secure Boot evidence varies by Mac hardware and OS version; unavailable evidence remains unknown.
- Manual evidence is not independently verified.
- MDM, identity-provider, escrow, backup, disclosure, and classification controls require organizational integration.
- Current DoD, NIST, Apple, CISA, contractual, legal, privacy, sanctions, and export-control requirements must be reviewed by qualified personnel.
