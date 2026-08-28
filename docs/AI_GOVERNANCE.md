# AI Governance and Mission Assurance

MSAA is designed to support DoD Responsible AI principles through responsible ownership, equitable review, traceable evidence, reliable bounded operation, and governable stop/change controls. CISA Secure by Design informs safe defaults, least privilege, explicit authorization, secure failure, auditability, and burden reduction. This is alignment, not government approval or compliance certification.

NIST AI RMF functions are addressed as follows: Govern defines precedence, accountability and risk acceptance; Map records mission, stakeholders, context and harm; Measure requires sources, versions, test evidence and uncertainty; Manage selects advisory/simulation fallbacks, approvals, stops, rollback and recovery. NIST CSF functions are mapped to governance/authorization, asset and evidence identification, protective controls, detections and collector health, incident response, and recovery evidence.

MITRE ATT&CK® is used only as a behavior taxonomy for threat modeling, mapping, detection engineering, incident analysis, defensive validation, and authorized emulation. Every stored mapping should carry domain, ATT&CK data version, retrieval/validation date, tactic and technique/sub-technique identifiers and names, purpose, evidence, detection/mitigation/data-source relationships, confidence and basis, reviewer, review status, and validation status. The local STIX provider rejects unknown IDs and fails safely when no approved dataset is installed. ATT&CK does not establish authority or coverage.

## Precedence and human control

Mandatory precedence is law/legal authority; owner authorization; rules of engagement; classification/privacy/export/sanctions/records requirements; platform safety/security; organization policy; MSAA configuration; engagement instructions; user requests. Consequential actions need separately scoped, time-limited, auditable human approval. Generic assent is insufficient. Safeguard changes require peer security review, negative tests, versioned policy, rollback, documentation, and authorizing-official acceptance where applicable.

## Information integrity

Material outputs distinguish Verified Facts, Supplied Evidence, Assumptions, Inferences, Unknowns, Conflicting Evidence, Validation Required, Recommended Actions, Human Approval Required, Sources, retrieval date, framework/data version, and Confidence Basis. Unverified identifiers, telemetry, sources, legal authority, tests, capabilities, and mappings remain `Not verified`, `Source unavailable`, `Framework version not configured`, `Insufficient evidence`, or `Requires human validation`. Executable guidance documents environment, privileges, effects, unintended effects, logging, validation, rollback/recovery, and actual test status.

## Confidentiality and incidents

NDA work uses need-to-know access, roles, minimization, redaction, retention, approved encryption, sensitivity labels, export controls, approved environments, and incident contacts. NDA status never weakens authorization, approval, audit, or data policy. Passwords, tokens, keys, authentication headers, cookies, unnecessary personal information, and full classified/controlled documents are not logged. Protected information is not sent externally without category/provider authorization.

On authorization, policy, privacy, model-validation, audit, rollback, or recovery failure, suspend operational execution; record a redacted event; preserve evidence; notify the accountable contact; contain safely; execute approved rollback/recovery; and reassess before resumption. Incidents involving a governance safeguard require root-cause review, impact assessment, tests, versioned corrective action, and controlled redeployment.
