# Cyber Resilience Score

The Cyber Resilience Score measures evidenced preparedness to detect, investigate, contain, recover from, and improve after incidents. It is separate from the MSAA Security Score, which measures weaknesses and threat exposure.

Calculation version 1.0 uses eight fixed categories totaling 100%: detection 20%, response 18%, containment 12%, recovery 18%, identity 10%, supply chain 10%, vulnerability 6%, and configuration 6%. Controls within each category also total 100%. A control earns its published weight only when an explicit passing state and evidence reference are both present. Failed and unmeasured controls earn no credit and remain visible.

Inputs are normalized from existing Continuous Security Assurance, Attack Simulation, Secure Evidence Collection, Emergency Response, Identity Attack Detection, Supply Chain Trust Graph, Software Attestation, Threat Exposure Management, Security Control Validation, and Security Regression artifacts. The engine does not run simulations or containment itself.

Assessments record their calculation version, evidence sources, category scores, control explanations, weaknesses, recommendations, and changes from the previous assessment. Stored history is protected by SHA-256 integrity verification.

The score is not a guarantee that an incident will be detected or survived, does not certify compliance, and does not replace incident responders or security leadership. Framework mappings cover NIST CSF 2.0, NIST SP 800-61, NIST SP 800-207, CISA Cybersecurity Performance Goals, and relevant NIST SP 800-53 controls.
