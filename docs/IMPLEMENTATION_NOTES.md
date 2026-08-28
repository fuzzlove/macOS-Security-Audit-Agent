# Authorized-Use Governance Implementation Notes

## Decisions and assumptions

The established Python/PySide6/SQLite architecture was retained. `mission_governance.py` is the central typed policy boundary and reuses local storage and SHA-256 audit patterns. JSON Schema is used because the repository already has `schemas/`; YAML is configuration documentation and intentionally adds no parser dependency. Default mode is advisory. No environment variable, license, NDA, developer/debug mode, role, or assertion can activate operational mode.

EULA acceptance is deliberately required on every GUI application launch. The SQLite store keeps a versioned event history rather than treating a prior launch's acceptance as sufficient. This records agreement to proposed software terms only and is not authorization evidence.

After the application database opens, each accepted launch also records a `governance_eula_accepted` entry in the existing background-monitor event stream. It is log-only, never raises a security alert, bypasses deduplication so each launch is retained, and contains only a pseudonymous local-user reference, versions, and timestamp.

## Implemented

Mission, governance, draft EULA, authorization guide, strict schema, policy defaults, authorization evaluator, exact asset/network/account/action/effect/technique/jurisdiction checks, approval and stop checks, redaction, chained audit events, EULA acceptance store, material-output structure, and approved local ATT&CK STIX provider boundary.

## Limitations and required review

The draft EULA requires qualified legal review. Policy/configuration, classifications, retention, jurisdictions, export/sanctions handling, contacts, and authorization templates require security, privacy, export-control, system-owner, and Authorizing Official review. The current package does not authenticate approver identity, validate document signatures, provide enterprise RBAC/key management, securely delete every filesystem type, or import classified authorization documents. Full wiring into every historic UI button, daemon RPC, CLI command, plugin, and helper is ongoing; callers not yet wired retain their existing safeguards and must not be described as centrally authorization-enforced.

ATT&CK STIX is not bundled; an administrator must obtain an approved official dataset, protect it locally, record its version/retrieval date, and configure the provider. No MITRE certification or complete coverage is claimed.

## Unresolved EULA placeholders

`{{ORGANIZATION_LEGAL_NAME}}`, `{{EULA_VERSION}}`, `{{EFFECTIVE_DATE}}`, `{{GOVERNING_LAW}}`, `{{CONTACT_EMAIL}}`, `{{SECURITY_CONTACT}}`, `{{PRIVACY_CONTACT}}`.
