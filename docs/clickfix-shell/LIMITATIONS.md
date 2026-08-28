# Limitations

- This control reduces ClickFix risk but cannot guarantee prevention.
- Shell startup files and adapters are not tamper-resistant boundaries.
- Noninteractive scripts and terminal configurations that bypass initialization are outside adapter enforcement.
- Commands launched by GUI applications may not use an instrumented shell.
- Script Editor and URL-scheme execution require endpoint-level coverage.
- Exact signatures and bounded decoding cannot catch every obfuscation.
- Generic PTY fallback is best effort and must be explicitly opted into.
- Endpoint Security needs Apple-approved capabilities, signing, deployment, and successful initialization.
- Audit mode should precede blocking; review false-positive metrics before lowering thresholds.
- The shell scanner is currently a Python executable entry point, not a universal native scanner binary. The native Swift agent builds separately.
- Bash/Readline versions that cannot expose the complete editable buffer report degraded coverage and require explicit proxy opt-in for paste-layer protection.
- Interactive PTY behavior must be qualified on every supported macOS, shell, editing mode, and terminal emulator before managed blocking. Static source tests do not prove job-control behavior on every terminal.
