# Compliance-control mapping

This feature is designed to align with, support implementation of, and provide evidence for controls; it is not certification, authorization, or a statement that an organizational control is satisfied. Control selection, parameters, inherited controls, operating environment, assessment procedures, and evidence review remain organizational responsibilities.

- AU-2/AU-3/AU-12: typed receipt records, identity, time, source, outcome, sequence, and generation tests.
- AU-5: visible degraded state, bounded emergency fallback, queue/storage pressure accounting, and recovery audit.
- AU-6: searchable CLI/Alert Center, correlation fields, aggregates, and integrity review.
- AU-9: keyed chains, restrictive deployment permissions, and integrity verification.
- SI-4/SC-5: monitored pressure, bounded notification/cardinality/source state, reserved priority capacity, flood detection and consolidation.
- IR-4: incident IDs, evidence export, priority handling, and idempotent response reservation.
- AC-6/CM-5: read-only user view and authorized narrow suppression workflow.
- CM-3: policy-versioned suppression and chained change records.
- SA-11: adversarial, concurrency-oriented, restart, tamper, and benchmark tests.

The requested identifiers were checked against the official [NIST SP 800-53 Rev. 5, current Release 5.2.0 page](https://csrc.nist.gov/Pubs/sp/800/53/r5/upd1/Final). NIST cautions that mappings are contextual and not necessarily one-to-one. [CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) is an outcome taxonomy and does not prescribe implementation. The architecture also supports Detect/Respond/Recover evidence and governance of policy changes.

DoD RMF use requires system categorization, control tailoring, implementation statements, assessment, risk acceptance, and authorization outside this repository. DISA publishes current Apple macOS guidance through the official [STIG document library](https://public.cyber.mil/stigs/downloads/); this feature does not claim STIG compliance. CIS Apple macOS Benchmark mappings likewise require licensed/current benchmark review and host evidence. MITRE ATT&CK tags are event context, not proof of technique detection completeness.

The threat model, bounded defaults, customer-visible degradation, and transparent limitations are designed to align with CISA's [Secure by Design principles](https://www.cisa.gov/sites/default/files/2023-10/Shifting-the-Balance-of-Cybersecurity-Risk-Principles-and-Approaches-for-Secure-by-Design-Software.pdf), particularly ownership of customer security outcomes and transparency. This is not CISA approval.
