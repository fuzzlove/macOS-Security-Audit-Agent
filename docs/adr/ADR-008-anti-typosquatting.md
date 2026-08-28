# ADR-008: Deterministic Anti-Typosquatting Analysis

## Status

Accepted for controlled feature development.

## Context

Owners need realistic defensive variants without a string-permutation flood, opaque remote model, unsafe candidate interaction, or misleading availability claims.

## Decision

Use local deterministic generators behind typed asset and namespace models. Keep human-typing and impersonation scores separate. Normalize according to the target registry before deduplication. Use versioned local Unicode and keyboard data. Put passive network access behind provider adapters and explicit consent. Use RDAP rather than shell WHOIS. Never open candidate websites or retrieve package artifacts.

## Alternatives considered

- Remote generative AI: rejected because output and disclosure are difficult to audit.
- Exhaustive permutations: rejected because quality and resource use are unbounded.
- DNS-only availability: rejected because absence of DNS records is not registration availability.
- Browser or package-manager inspection: rejected because it interacts with potentially hostile content.

## Security consequences

Candidate generation is reproducible and offline. Provider destinations can be allowlisted and bounded. Unicode and output controls are testable. The reduced bundled Unicode/locale subset limits coverage and must be labelled accurately.

## Operational consequences

Locale and confusable data require reviewed developer updates, checksums, fixtures, and release evidence. Registry outages affect only requested status enrichment.

## Migration consequences

New tables use a feature-specific schema marker. Existing MSAA tables and integrity manifests are not rewritten. A final authorized integrity signing workflow is required after the feature and release tree are approved.
