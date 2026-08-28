# Proprietary Detection Protection

Public schemas, collectors, UI contracts, proprietary correlation, risk models, customer policy, and signing infrastructure must remain separate. Standard logs and exports disclose stable rule identifier, version, category, result, and structured error code—not complete formulas, weights, thresholds, rule expressions, anti-evasion logic, customer secrets, or tracebacks.

Production rule bundles are signed and versioned. The loader verifies an Ed25519 signature against a pinned public trust root before parsing and records only version and digest in routine evidence. Invalid bundles fail closed for proprietary analysis while baseline monitoring remains operational. Private signing keys never belong in source, configuration, the application bundle, or diagnostic logs.

Python cannot be made impossible to reverse engineer. Protection depends on architecture, access control, signed releases, hardened runtime, notarization, native system-extension signing, controlled builds, dependency pinning, provenance, secret scanning, key rotation, and need-to-know handling.

Source-leakage and key-compromise response must preserve evidence, revoke affected access, rotate trust material through the approved release process, assess customer diagnostic exposure, and issue a signed replacement release. Legal confidentiality notices require legal review.
