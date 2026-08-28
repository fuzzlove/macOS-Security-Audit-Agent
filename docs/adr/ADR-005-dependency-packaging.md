# ADR-005: Dependency Packaging

Status: Accepted

## Context
Headless users should not receive GUI/native dependencies.

## Decision
Keep core dependencies empty and expose GUI, network, forensics, crypto, exports, build, test, development, and all extras. Native origins require architecture validation in packaged releases.

## Alternatives considered
A monolithic dependency set and runtime installation were rejected.

## Security consequences
Missing optional packages disable only mapped capabilities; no silent pip/Homebrew execution occurs.

## Operational consequences
Constraints are maintained per qualified build runtime.

## Migration consequences
Existing extras remain aliases where practical.
