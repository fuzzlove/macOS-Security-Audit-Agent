# Security Model

MSAA separates the unprivileged GUI/CLI, user notifier, system daemon, Endpoint Security sensor, and narrowly scoped containment helper. The GUI never runs as root. Privileged installation is explicit and headless. Inputs to subprocesses are argument arrays with timeouts; no runtime package installation, downloaded-code execution, SIP/Gatekeeper bypass, or automatic TCC modification is permitted.

Release controls align with NIST SSDF/SP 800-218, SLSA provenance principles, OWASP supply-chain guidance, and CIS macOS hardening concepts. These are mappings, not certification claims.
