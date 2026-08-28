# ADR-002: Python Support

Status: Accepted

## Context
CLI, GUI, packaging, and deprecated system runtimes have different support envelopes.

## Decision
Python 3.9 is doctor/bootstrap-only; 3.10–3.13 support CLI/GUI; 3.14 is headless-first; release packaging uses 3.12. Stage 0 auto-selects a mode-compatible interpreter.

## Alternatives considered
Treating every `python3` equally and forcing PySide6 into core dependencies were rejected.

## Security consequences
Qt is not imported before runtime and GUI-context guards pass.

## Operational consequences
CI tests each declared tier; GUI qualification is narrower than CLI.

## Migration consequences
Old entry points remain and receive guided runtime selection.
