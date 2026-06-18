# Changelog

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
