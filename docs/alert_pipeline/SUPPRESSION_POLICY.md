# Suppression policy

Suppressions require exact supported fields, owner, timezone-aware expiration, reason, ticket, authorizing identity, and policy version. The default maximum duration is 24 hours. Supported exact fields are rule ID, event type, source ID, signing identifier, user UID, and host ID. Wildcards, regular expressions, empty conditions, indefinite/expired/excess-duration rules, and ordinary protected-event suppression are rejected.

Matching events remain in the security ledger and aggregate counts; only presentation is eligible for suppression. Protected events ignore ordinary matches. A hardened protected-maintenance workflow must explicitly classify the protected scope and requires a distinct approval identity. Creation and revocation are chained audit actions. Expired/revoked rules remain reviewable; they do not match.

Read with `msaa alerts suppression list`. Creation/revocation through `msaa alerts suppression create|revoke` requires effective root and is intended to be invoked only through the installed privileged MSAA authorization workflow. Root identity alone is not a complete organizational approval; deployments must enforce operator/ticket validation and any two-person policy at the privileged service boundary. MSAA never asks for or stores an administrator password.
