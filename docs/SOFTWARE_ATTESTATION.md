# Software Attestation

MSAA Software Attestation consumes existing software inventory, Apple signing assessment, SHA-256 evidence, approved baselines, Supply Chain Trust Graph results, Threat Exposure results, and Security Posture Graph relationships. It does not rescan, execute, modify, block, or remove software.

An attestation independently evaluates identity, integrity, provenance, notarization/Gatekeeper state, behavioral context, and vulnerability or supply-chain context. Every accepted input must identify the application and carry an evidence reference. Missing baselines and missing telemetry are reported as unknown, not healthy.

Profiles may represent enterprise, education, or government approval requirements. Policy results are `approved`, `review`, or `blocked_pending_approval`. The final state never performs blocking: the latter result records that an administrator decision is required.

Assessments and stored histories are integrity-protected with SHA-256. A failed hash comparison records both baseline and observed hashes, associated evidence, and change type. It does not claim malware or endpoint compromise.

Framework mapping includes NIST SP 800-53 SI-7, SA-10, SA-11, SR-4, and CM-5; NIST CSF 2.0 asset, platform security, data integrity, monitoring, and supply-chain outcomes; and NIST SSDF software integrity and provenance practices.
