# Architecture

`scan_cli` is the strict JSON stdin/stdout boundary. `shell_tokenizer` performs bounded lexical normalization; `shell_scanner` evaluates relationships and bounded literal decoding; `shell_config` applies managed-before-user plist policy; `shell_events` serializes privacy-safe JSONL. zsh and Bash adapters scan complete editable buffers at paste/accept boundaries. `msaa-safe-shell` is an opt-in PTY fallback and forwards input unchanged when the real shell is not the foreground process. The existing native shortcut sensor and future `MSAAEndpointMonitor` are separate correlation layers.

No component evaluates submitted text, invokes a shell to inspect it, performs network access, or places raw text in argv.

The current pre-submission scanner is the repository's headless Python implementation, launched as `msaa-clickfix-scan`; the signed Swift ClickFix Guard agent is a separate native shortcut/telemetry component. Packaging a universal native scanner binary remains a release-engineering item and must not be inferred from the Swift agent build. The Python scanner is local-only and uses no third-party runtime library for tokenization, hashing, decoding, or rule evaluation.

The shell adapter/proxy is the primary interim enforcement layer. The existing MSAA System Monitor is only an event bridge: it consumes bounded, schema-validated, privacy-safe JSONL records using a durable cursor and emits MSAA events without raw or decoded commands. This avoids another resident monitor while keeping pre-execution decisions in the only component that owns the interactive line buffer.

The generic proxy resolves the account shell through `getpwuid`, creates a pseudo-terminal, switches its controlling input into raw mode, forwards resize and termination signals, and restores terminal settings during cleanup. It inspects bracketed paste only while the shell—not an editor, pager, database client, or SSH child—is the foreground process. Warn mode holds the paste in process memory and requires an eight-character unpredictable challenge within 60 seconds; the restored line has no trailing newline.

The Swift package exposes a compile-gated `MSAAEndpointMonitor` library interface for later process-execution correlation. It contains no default operational ES client and truthfully reports that entitlement/signing and successful initialization are required.
