# Persistence Radar Integration Review

Source project: https://github.com/fuzzlove/macOS-Persistence-Radar

## License Notes

Review date: 2026-06-29.

The source repository was reviewed as an upstream inspiration source for macOS persistence visibility. A root `LICENSE` file was not available from the repository paths checked during this integration pass. Because license terms could not be confirmed from a root license file, MSAA does not blindly copy source files from macOS Persistence Radar in this integration.

Implementation in MSAA is independently written and integrated into native MSAA models, scanners, reports, settings, and Pre-UAT audit workflows. If upstream code is imported later, the license must be confirmed first and required notices must be preserved.

## Files Reviewed

- Source repository README and public feature descriptions.
- Public CLI/workflow concepts described by the project, including scan, coverage, chains, posture, timeline, malware knowledge base, doctor, baseline, watch, and export workflows.
- Public detection coverage concepts for launchd, browser persistence, scheduled jobs, shell startup, profiles, extensions, privileged helpers, PATH hijack, support directories, users/groups, and TCC visibility limitations.

## Functionality Imported

No source files were copied into MSAA during this pass.

## Functionality Adapted

- Persistence inventory model.
- Read-only scanner registry.
- LaunchAgents and LaunchDaemons plist parsing.
- Browser native messaging host and extension inventory concepts.
- Shell startup, scheduled job, privileged helper, profile, certificate, extension, support-directory, PATH, user/group, and TCC indicator coverage concepts.
- Risk scoring, trust scoring, baseline comparison, timeline, chain view, coverage, diagnostics, malware-pattern correlation, and reports.
- Pre-UAT checks for scanner registry, launchd scan, baseline/timeline/chain/report workflow, and no destructive actions.

## Functionality Not Imported

- Any upstream source code with unclear license status.
- Standalone application/UI concepts that would duplicate MSAA.
- Destructive remediation or unload/delete actions.
- Browsing history, cookies, passwords, keychain secrets, private keys, or TCC bypass behavior.
- Aggressive support-directory searching beyond bounded read-only limits.

## Compatibility Concerns

- Upstream license confirmation is required before any direct source reuse.
- macOS visibility varies by Full Disk Access, user permissions, OS version, and managed-device policy.
- Scanner results must be described as visibility and risk indicators, not definitive malware or compliance conclusions.

## Attribution Requirements

MSAA documentation and acknowledgements include:

“MSAA Persistence Intelligence incorporates concepts and, where compatible, implementation ideas from macOS Persistence Radar, an open-source macOS persistence visibility and audit project.”
