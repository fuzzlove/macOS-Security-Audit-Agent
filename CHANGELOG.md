# Changelog

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
