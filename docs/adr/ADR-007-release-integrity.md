# ADR-007: Release Integrity

Status: Accepted

## Context
Each architecture artifact needs independent provenance and integrity evidence.

## Decision
Generate SHA-256 sums, architecture-declared release manifest, CycloneDX SBOM, SLSA-shaped provenance, signing metadata, and notarization state. Ordinary execution never rewrites baselines.

## Alternatives considered
One shared hash for multiple architectures and unsigned/unverifiable release claims were rejected.

## Security consequences
Modified, unsigned, wrong-architecture, stale, and unverifiable artifacts remain distinct states.

## Operational consequences
Developer ID and notarization credentials are external keychain/environment inputs.

## Migration consequences
Existing integrity manifests remain; release evidence augments rather than silently replaces them.
