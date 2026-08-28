# Deployment and Rollout

1. Audit: collect score distributions, false positives, adapter coverage, and event delivery.
2. Warn: interrupt medium/high risk, measure overrides, and review administrative workflows.
3. Block: block high-confidence relationships and use only exact-hash narrow exceptions.
4. Endpoint correlation: add an appropriately signed/entitled Endpoint Security or approved EDR integration.

User installation does not change the login shell or terminal-emulator settings. Managed deployment installs reviewed root-owned files and the sample `com.msaa.clickfix` preference using MDM; system-managed settings take precedence. Test deployment on canaries before fleet rollout.

The ClickFix Guard page can run the user installer directly; it deliberately does not request `sudo`. Open a new terminal after installation, then select **Verify Shell Guard**. The page reports file-integrity status, active login-shell adapter, optional proxy status, policy source, latest privacy-safe event, and whether the existing System Monitor has consumed the journal. `zsh` and supported interactive Bash sessions use direct adapters. Other shells require explicit opt-in to `msaa-safe-shell`; MSAA does not silently change a login shell.

Command-line installation preserves the required unmanaged default of audit mode unless enforcement is explicitly selected. Use `scripts/install-clickfix-shell-guard.sh --mode warn` to hold suspicious submissions for review, or `scripts/install-clickfix-shell-guard.sh --mode block` to discard high-confidence chains. Audit mode detects and records but does not interrupt execution. The installer prints this distinction prominently; system-managed policy takes precedence.

The installer runs a harmless stdin/JSON scanner self-test before writing any startup-file block, creates timestamped backups, uses idempotent markers, and records installed hashes. User-level configuration cannot create an exact-hash exception; such exceptions are accepted only from the system-managed preference domain. The generic proxy remains opt-in and must not be configured as a login shell without a separately tested rollback procedure.

If zsh reports that protected widgets were replaced, first use **Install or Repair Shell Guard**, confirm the managed block remains at the end of `.zshrc`, and open a new terminal. The adapter wraps both the canonical `accept-line`/`bracketed-paste` widgets and common Return bindings. A later-loaded plugin may legitimately replace them; that condition is degraded pre-execution coverage, not proof of malicious tampering. The integrity alert is rate-limited to one message until coverage recovers.
