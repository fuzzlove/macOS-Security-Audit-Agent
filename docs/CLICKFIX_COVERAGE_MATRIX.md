# ClickFix Coverage Matrix

Measured offline corpus: 96/96 passed (100.0%). No fixture was executed and no network API is used by the runner.

| Category | Passed | Total | Coverage |
|---|---:|---:|---:|
| applescript | 5 | 5 | 100.0% |
| benign | 12 | 12 | 100.0% |
| chain_correlation | 5 | 5 | 100.0% |
| credential_access | 8 | 8 | 100.0% |
| destructive_symbolic | 8 | 8 | 100.0% |
| driveby | 7 | 7 | 100.0% |
| encoding | 7 | 7 | 100.0% |
| multiline | 7 | 7 | 100.0% |
| obfuscation | 12 | 12 | 100.0% |
| persistence | 5 | 5 | 100.0% |
| security_bypass | 6 | 6 | 100.0% |
| simple | 8 | 8 | 100.0% |
| staging | 6 | 6 | 100.0% |

## Environment status

| Environment | Status | Basis |
|---|---|---|
| zsh | tested | scanner corpus and adapter source contract |
| bash | tested | scanner corpus and adapter source contract |
| Apple Terminal | not_tested | interactive qualification required |
| iTerm2 | not_tested | not installed/automated |
| Warp | not_tested | not installed/automated |
| VS Code integrated terminal | not_tested | not launched |
| Cursor integrated terminal | not_tested | not launched |
| SSH | not_tested | no remote session opened |
| tmux | not_tested | no interactive PTY qualification |
| screen | not_tested | no interactive PTY qualification |
| Script Editor | simulated | endpoint context only; no AppleScript executed |

## Interpretation

`pre_execution_scanner` and `correlated_pre_execution` are blocking-capable test paths. `simulated_endpoint_context` validates deterministic context mappings only; it is not proof of operational Endpoint Security coverage. Terminal-product coverage requires manual qualification on installed products.

## Performance

Mean 0.4046 ms; p95 0.8846 ms; maximum 4.8007 ms; corpus timeouts 0. The separate timeout regression forces and verifies the scanner timeout path. Environment: `macOS-26.5.2-x86_64-i386-64bit-Mach-O`, Python 3.13.14.
