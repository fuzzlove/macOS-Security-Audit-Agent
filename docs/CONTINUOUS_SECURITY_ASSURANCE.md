# Continuous Security Assurance Engine

The Continuous Security Assurance Engine (CSAE) is an evidence-normalization and posture-history layer over existing MSAA detectors. It does not create another process, file, network, persistence, vulnerability, or identity collector.

## Assurance model

CSAE evaluates five domains: identity, software, configuration, threat exposure, and recovery readiness. Every signal records its observed value, evidence references, score credit, risk severity, framework context, explanation, and recommended analyst action.

Missing evidence is `unknown`, receives no trust credit, and reduces evidence coverage. A missing current observation is not reported as a regression because absence of telemetry does not prove that a control changed. Coverage loss remains visible through the evidence-coverage percentage and `INSUFFICIENT EVIDENCE` trust decision.

Domain scores are weighted into a 0–100 posture score. The snapshot records the complete calculation explanation and a SHA-256 integrity hash. Scores are decision support, not certification or authorization.

## Changes and correlation

CSAE compares two evidence-backed snapshots. A transition from validated to concern is a regression; concern to validated is an improvement. High and critical regressions can be transformed into existing MSAA-compatible alert payloads. Improvements do not generate security alerts.

The initial cross-module correlation requires concurrent concern evidence for unsigned software, suspicious persistence, and suspicious network activity, plus at least two newly regressed source signals. It reports a possible persistence-deployment pattern and explicitly does not claim compromise.

## Storage and safety

`SecurityAssuranceRepository` stores snapshots in `security_posture_history` and changes in `security_changes`. Saves use one SQLite transaction. CSAE only observes, scores, records, explains, and recommends; it never disables controls, removes software, or initiates containment.

Native event completeness, authorization context, vulnerability-feed completeness, and real-time scheduling remain deployment responsibilities. CSAE exposes missing evidence rather than inferring a healthy posture.
