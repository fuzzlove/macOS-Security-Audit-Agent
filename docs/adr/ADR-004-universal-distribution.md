# ADR-004: Universal Distribution

Status: Accepted

## Context
Native dependencies make unverified universal2 merging unsafe.

## Decision
Publish native arm64 and x86_64 apps. Allow universal2 only when Python and every embedded Mach-O have both slices.

## Alternatives considered
Merging separately frozen apps and treating Rosetta as native evidence were rejected.

## Security consequences
Artifact architecture is recorded and verified before release.

## Operational consequences
Intel and Apple Silicon runners are mandatory external infrastructure.

## Migration consequences
Users select an architecture-specific app; Python wheel remains architecture-independent while it contains no native payload.
