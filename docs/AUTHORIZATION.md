# Authorization and Operational Modes

MSAA defaults to `ADVISORY`. `SIMULATION` uses synthetic or mock data. `LAB_EXECUTION` requires an identified isolated lab, sandbox, training system, or test fixture. `AUTHORIZED_OPERATIONAL` requires a current approved authorization context whose asset, identity, action, effect, technique, jurisdiction, time, audit, rollback, recovery, and human approvals match the request.

The precedence order is: applicable law and valid legal authority; asset-owner authorization; approved rules of engagement; classification/privacy/export/sanctions/records requirements; platform requirements; organizational policy; administrator/developer configuration; engagement instructions; end-user requests. Lower levels never override higher ones. A license or NDA is not system authorization.

## Human-readable context template

Record mission and engagement IDs; protected authorization reference and hash; authorizing entity; accountable approver; system/asset owner; environment and validity window; in/out-of-scope assets, networks, identities, sources, actions and effects; allowed/prohibited ATT&CK behavior; jurisdictions; classification and controlled categories; retention/log/evidence rules; contacts; stop conditions; rollback/recovery plans; approval points; framework versions; and output mode. Never embed credentials, private keys, tokens, warrants, classified documents, or full sensitive authorization documents.

Operational execution stops for missing, disputed, suspended, revoked, future, or expired authorization; scope mismatch; prohibited behavior/effects; unexpected controlled information; stop instruction; absent approval; unverifiable target/context; exceeded thresholds; missing rollback/recovery/audit; or insufficiently validated consequential model output. Rollback, recovery, evidence preservation, defensive guidance, advisory analysis, and simulation remain available.
