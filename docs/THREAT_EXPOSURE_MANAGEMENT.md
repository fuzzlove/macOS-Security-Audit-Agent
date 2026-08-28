# Threat Exposure Management

Threat Exposure Management correlates existing MSAA inventory, vulnerability, supply-chain, identity, configuration, Zero Trust, CSAE, threat-intelligence, and Security Posture Graph evidence. It does not perform another vulnerability scan.

## Applicability and intelligence

A vulnerability exposure requires an exact normalized product match, a confirmed affected installed version, and evidence references. Unparseable or missing versions do not create an exposure. CISA KEV can increase an already-applicable exposure's priority but cannot create applicability by itself.

Threat-intelligence matches require an indicator type/value, source, timestamp, confidence, reference, and status. “Known exploited” means exploitation is confirmed in the wild; it does not mean the assessed endpoint was exploited or compromised.

## Scoring

Scoring combines CVSS contribution with sourced exploit status, asset importance, endpoint reachability, privileged-user context, Zero Trust state, software signature evidence, and supported graph-path context. CVSS alone is neither the score nor the priority.

Every exposure records its score factors, evidence, confidence, uncertainty, risk explanation, recommendation, and expected risk reduction. Remediation order is deterministic and is decision support for an authorized change workflow.

## Safety and integration

The module does not uninstall software, change configuration, disable accounts, block indicators, create tickets externally, or initiate incident response automatically. Critical records can produce an authorization-required evidence and investigation recommendation.

SQLite stores integrity-hashed assessments and normalized exposure records. JSON/HTML reports and the Threat Exposure Management dashboard show critical exposures, KEV findings, attack-path context, trends, evidence, and recommendations.

Data-source freshness and completeness remain visible limitations. NVD, KEV, vendor, MISP, OpenCTI, and other intelligence must be supplied through approved MSAA ingestion and caching workflows.
