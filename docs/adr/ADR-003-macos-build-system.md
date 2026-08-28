# ADR-003: macOS Build System

Status: Accepted

## Context
MSAA already uses PyInstaller and PySide6 with working package-resource hooks.

## Decision
Retain PyInstaller, pin the build environment, embed Python, and produce native app bundles on matching hardware.

## Alternatives considered
Nuitka, Briefcase, and cx_Freeze would require migration without resolving entitlement or dual-hardware qualification gates.

## Security consequences
Nested Mach-O validation and signing precede outer bundle signing.

## Operational consequences
Python 3.12 is the release baseline.

## Migration consequences
Existing spec/resources remain authoritative and gain architecture/signing parameters.
