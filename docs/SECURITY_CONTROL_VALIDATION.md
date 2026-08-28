# macOS Security Control Validation Framework

This framework adds declarative expected-state validation to MSAA's existing security-control registry and collectors. It does not create a second monitoring system or execute configuration changes.

Each validation control identifies its existing monitored control, frameworks, evidence key, expected state, comparator, severity, remediation guidance, review command, and ATT&CK context. Enterprise, education, government, and critical-infrastructure profiles select controls and severity overrides.

Evidence must include a value, collector source, collection timestamp, and evidence reference. Missing, malformed, future-dated, or stale evidence produces `not_assessed`, never `passed`. Results are `passed`, `failed`, `not_assessed`, or `excepted`.

Exceptions require a reason, approver, approval time, expiration time, and evidence reference. An exception is not a passing control and receives no compliance-score credit. The score is passed controls divided by all required controls, with counts and status shown explicitly.

Remediation output is guidance only and follows `review → approve → apply_external_change → verify`. MSAA does not execute the command, edit TCC, change accounts, disable protections, or claim certification.

SQLite stores declarative controls, integrity-hashed assessments, and individual validation events. Reports and the dashboard preserve evidence, uncertainty, failures, exceptions, not-assessed controls, regressions, mappings, and remediation.
