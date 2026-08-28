# ADR-001: Platform Support

Status: Accepted

## Context
MSAA needs explicit macOS, architecture, translation, and degraded-mode boundaries.

## Decision
Support macOS 12+ with native arm64 and x86_64 artifacts. Detect native hardware separately from process architecture. Rosetta is supported for diagnostics but never substitutes for native release qualification.

## Alternatives considered
One architecture and Rosetta-only compatibility was rejected. Unconditional universal2 claims were rejected.

## Security consequences
Wrong-architecture helpers fail closed; unavailable APIs become explicit capability states.

## Operational consequences
Two native build/test lanes are required.

## Migration consequences
Existing user data paths and identifiers remain unchanged.
