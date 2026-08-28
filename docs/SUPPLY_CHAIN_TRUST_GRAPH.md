# Supply Chain Trust Graph

The Supply Chain Trust Graph extends MSAA's software inventory, signing assessment, supply-chain findings, vulnerability data, typosquatting analysis, and Security Posture Graph. It does not rescan or modify installed software.

Relationships require evidence references and identify their source, timestamp, confidence, explanation, and risk impact. Supported entities include software, developers, certificates, builds, package sources, dependencies, vulnerabilities, and threat indicators.

SPDX and CycloneDX documents are ingested only when components and the document carry evidence references. Unsupported or absent SBOMs are reported explicitly. Dependency and vulnerability relationships require exact supplied component identity; package similarity is labeled for review and never establishes maliciousness.

Trust begins neutral and is adjusted by signature validity, notarization, developer/certificate visibility, verified distribution source, exact vulnerable dependencies, sourced intelligence, update-identity changes, typosquatting evidence, and supported posture-graph paths. Unsigned or ad-hoc software receives a moderate review penalty, not a malicious verdict.

The dashboard and reports expose reasons, unknowns, SBOM status, developer/certificate evidence, dependencies, vulnerabilities, and risk relationships. Emergency-response output only recommends authorized evidence preservation; automatic blocking or removal is not supported.
