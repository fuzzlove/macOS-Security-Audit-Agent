# Detector integration guide

Existing detectors submit `BackgroundMonitorEvent`; the database adapter supplies durable accounting. New detectors register a `DetectorContract` with stable rule ID/version and explicit identity/material fields. Before production integration, the detector review record must also specify default severity, confidence model, protected classification, ATT&CK/CVE mappings, recommended aggregation/notification/response policy, required permissions, data-retention classification, sensitive/excluded fields, and adversarial fixtures.

Identity changes create a new alert; material changes notify within an identity. Never include timestamps, random IDs, display text, or insignificant attacker-controlled values in identity fields. Include security identity such as signing ID/hash, normalized path, user, destination, persistence location, device, action, or policy only when appropriate to that rule. Tests must show exact duplicates consolidate while every declared material change bypasses ordinary suppression.

Unknown optional fields may be retained only inside bounded, redacted `attributes`. Unknown schema versions fail closed and must create bounded health evidence at the producer/service boundary. Adding a future detector does not imply it prevents an unknown threat; it extends the set of evidence and policy MSAA can evaluate.
