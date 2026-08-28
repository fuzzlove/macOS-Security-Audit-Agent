# Changelog

## 1.0b Universal2 - 2026-08-28

- Rebuilt the macOS application with the validated Python 3.12.10 universal2 runtime for both Apple Silicon and Intel Macs.
- Enabled the public Stripe-hosted Checkout and signed-license activation flow for the live $10/month subscription Price while keeping Stripe and license-issuer secrets server-side.
- Added build-time SHA-256 bundle inventory generation and post-build verification; the release bundle verifies 704 protected files.
- Added `Mac-Audit-Agent-1.0b0-macos-universal2.zip` with SHA-256 `d206792ed9b7358b83025d73501c10f24fa24159d38c0ff1f8bb0d2f5aac0f2e`.
- The attached application is ad-hoc signed for local use. Developer ID signing and Apple notarization remain required before general public distribution.

- Added six dynamic egress-provider definitions, qualification states, safe runtime DNS destination validation, nonce validation, RDAP/RIR parsing, and explicit unqualified-provider UI status. Public availability, address ownership, ASN, and RIR are no longer represented as static facts.
- Added an explicitly authorized 1–65535 TCP range option for qualified broad-port providers, with per-run traffic warnings and bounded 256-probe submission batches.
- Added the Ingress Network Segmentation controller foundation: primary-database migrations, scoped engagement/flow models, DNS-change enforcement, sender/receiver classification, audit hash chaining, authenticated offline-bundle primitives, safe native TCP/UDP backends, constrained Nmap integration, and honest UI capability gating.
- Consolidated segmentation under one **Network Segmentation** navigation page with separate Egress Tests and Ingress Tests tabs. Added fixed scoped Nmap profiles for common/top/full TCP, common/top UDP, DNS path, ICMP, ICMPv6, and selected IP protocols, plus hashed XML evidence export and inferred-result labeling.
- Hardened GUI regression tests to select Qt's offscreen backend before importing PySide6, preventing AppKit registration aborts under non-GUI Codex/CI parent processes.
- Fixed a Qt shutdown race in which a queued Network Monitor refresh could start a QThread after application teardown had begun, causing `QThread::~QThread()` to abort Python.

## Unreleased — Zero Trust and consultant workflow additions

- Added Network Segmentation with opt-in, scope-authorized outbound TCP reachability tests, approved-provider provenance, bounded concurrency/timeouts, SQLite evidence, multi-format reporting, UI/help integration, and offline mocked tests. Ingress, UDP, ICMP, and application-payload testing remain unsupported.
- Added asynchronous FileVault, explicit Secure Boot, SIP, firewall, and Not Signed Zero Trust evidence collection.
- Added manual evidence-state event logging and explainable rapid-checkoff review safeguards.
- Added complete running-software provenance export from Not Signed.
- Added Consultant Timesheet with local SQL history and XLSX, DOCX, PDF, TXT, and HTML exports.
- Added client-approved DNS configuration assurance, evidence export, and provenance-backed local intelligence imports.
- Added consent-based ARIN bootstrap and RIPE RDAP enrichment for live or historical connection evidence.
- Added missing contextual Help topics and beginner-oriented How To sections while retaining technical guidance.

## Unreleased

- Made the global Selected Item Details and Finding Remediation Guidance rail context-sensitive: it now collapses completely on unrelated or unselected pages, shows details alone for audit-command selections, and reveals remediation only for selected findings.
- Added mandatory sequential remediation after an unsuccessful Malware & History mastery assessment. Every response now shows the learner's selection, correct answer, explanation, linked lessons, and retention exercise; completion is recorded before another attempt.
- Added a one-time, per-local-user computer science ethics class and 100% assessment gate before EULA acceptance, with minimal versioned completion state, a privacy-restricted local event log, and one-time monitor-event mirroring; the EULA remains required every launch.
- Made ClickFix shell scripts the primary interim control: the ClickFix Guard page now installs, repairs, removes, verifies, and reports adapter/proxy coverage; the existing System Monitor consumes bounded privacy-safe shell events without command text. The signed native sensor remains optional defense-in-depth.
- Corrected a zsh ClickFix Guard false integrity alert by registering the canonical `accept-line` wrapper and rate-limiting genuine widget-replacement alerts until protection recovers.
- Added a 96-fixture, offline ClickFix adversarial validation corpus with destructive and credential symbolic tokens, simulated endpoint contexts, privacy-safe split-command correlation, no-execution/no-network tripwires, benign controls, measured JSON/Markdown reporting, and explicit untested terminal-environment status.
- Hardened ClickFix shell protection with managed-only exact-hash exceptions, threshold validation, bounded gzip/nested literal decoding, privacy-safe adapter and override events, expiring zsh challenges, raw-mode PTY restoration and signal forwarding, pre-install scanner validation, and a compile-gated `MSAAEndpointMonitor` Swift target.
- Added a centralized authorized-use governance foundation with advisory-by-default decisions, strict authorization-context schema, scoped human approvals, redacted chained audit events, local ATT&CK STIX validation boundary, anti-confabulation output structure, and mandatory per-launch draft EULA acceptance history.
- Decoupled intrusion report calculation from AI-summary persistence, added secure per-user atomic report storage and conservative legacy migration, and made Intrusion Detection and Flight Recorder share one fail-soft report snapshot.
- Replaced Windows-specific GUI font requests with Qt system-font selection and exposed report persistence state in runtime doctor diagnostics.

## 1.0b - 2026-07-06

### Added

- Beta release build for MSAA v1.0b with UAT hardening, framework readiness, support-page polish, notifier diagnostics, release evidence, and standards comparison guardrails.
- PyInstaller macOS arm64 app bundle artifacts refreshed for version 1.0b:
  - `MSAA-v1.0b-macos-arm64.zip` SHA-256: `1368d9aaf28022c99536aa8881e5fc77a347d5a75679908a626918466df6a989`
  - `MSAA-v1.0b-macos-arm64.tar.xz` SHA-256: `1e04adf4ede86be994190e829ae1419dd4ee47e7fdbd840d8fc78c4d67b3b54e`

## 0.1.1 - 2026-06-18

### Added

- Public-grade documentation set for architecture, privacy, deployment, threat model, operational safety, and government/enterprise evaluation
- Consolidated operational health reporting for app, SQLite, monitor, notifier, LaunchAgent, LaunchDaemon, detector, forecast, and report export readiness
- Expanded local privacy redaction helpers for usernames, IPs, MACs, hostnames, paths, and URL secrets
- Rule registry validation helpers for release readiness
- Public release checklist
- Alert pipeline trace evidence, Monitoring Coverage, Release Readiness, Trust Decay, Configuration Drift, Incident Mode, and SARIF export
- Apple Exposure Assessment naming and Mac-focused release readiness diagnostics

### Improved

- Documentation and release posture for local-first security evaluation
- Report and note redaction helpers
- Dashboard visibility for operational health
- GUI startup resilience when prior SQLite databases or state directories are root-owned or read-only
- Clean-install, PyInstaller, build, twine, and synthetic visible-alert release gates
# Unreleased

- Added an evidence-preserving RCE monitoring subsystem to the existing macOS system daemon, with deterministic behavior rules, degraded telemetry health, transactional/tamper-evident event storage, explicit human review dispositions, bounded offline CVE correlation, strict redaction, local CLI management, configuration, schema, tests, and documentation.
- Added deterministic macOS process-injection classification, stable novel-technique investigation identifiers, analyst evidence plans, and explicit bounded DFIR snapshots using fixed macOS tools; packet capture remains separately approved and never automatic.
- Expanded process-injection assurance with normalized invariant primitives, boot/start-stable identities, temporal behavior graphs, versioned templates, partial/variant/novel comparisons, ATT&CK validation snapshots, research and benign-context registries, tiered evidence bundles, access auditing, CLI triage, replay fixtures, and benchmarks.
