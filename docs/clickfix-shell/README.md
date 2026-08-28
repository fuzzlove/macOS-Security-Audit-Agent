# MSAA ClickFix Shell Guard

MSAA ClickFix Shell Guard reduces the risk that social engineering causes a copied command to execute before review. It does not guarantee prevention. It is MSAA's primary interim ClickFix control while appropriately entitled Apple Endpoint Security distribution is unavailable. The separately compiled Command+Space sensor remains optional defense-in-depth; it is not required for shell-buffer protection.

The scanner accepts one JSON request on standard input and emits one JSON decision. Raw and decoded commands are never persisted. Install user-only with `scripts/install-clickfix-shell-guard.sh`; verify with `scripts/verify-clickfix-shell-guard.sh`; remove with `scripts/uninstall-clickfix-shell-guard.sh`. The ClickFix Guard page provides the same install, repair, uninstall, verification, coverage, policy, last-event, and daemon-bridge status. Begin in `audit`, measure false positives and coverage, then progress through `warn`, `block`, and optional endpoint correlation.

The existing System Monitor may consume the shell guard's privacy-safe JSONL decisions and turn warnings, blocks, integrity failures, and degraded coverage into ordinary MSAA events. It never ingests command text. Enforcement remains in the interactive user shell because a root daemon cannot safely edit a shell's active line buffer.

Never broadly allow `curl | shell`. Separate retrieval, signature/hash verification, inspection, and execution.
