# macOS Security Audit Agent (MSAA)

MSAA is a local-first macOS audit, monitoring, and investigation platform. It is designed for analysts who need transparent evidence collection, reviewable alerts, and local-only reports without sending telemetry off the machine.

This repository is intended to be understandable, auditable, and safe enough for public review, institutional evaluation, and responsible internal deployment.

## What It Does

- Runs read-only macOS security audits
- Surfaces findings with evidence, confidence, and rule provenance
- Tracks review state, notes, suppression decisions, and case history
- Correlates events into investigation patterns and flight-recorder timelines
- Provides Apple Security Forecast summaries with low-noise grouping
- Supports optional user LaunchAgent mode and optional root-owned system LaunchDaemon mode
- Exports HTML and JSON reports locally
- Preserves evidence snapshots before cleanup or remediation

## What It Does Not Do

- No telemetry
- No cloud dependency
- No browser history extraction
- No cookie, token, password, or keychain extraction
- No hidden persistence
- No stealth behavior
- No offensive exploitation
- No hack-back or retaliation
- No automatic destructive cleanup
- No remediation without user approval

## Safety Model

The default mode is conservative.

Safe by default:

- no packet capture unless explicitly chosen
- no aggressive scans unless explicitly chosen
- no full localhost scan unless explicitly chosen
- no destructive cleanup by default
- no system daemon install by default
- no remediation execution by default
- no automatic uploads
- no automatic cloud enrichment using private data

Important features that can increase risk always require explicit user action and a warning.

## Privacy Model

All data stays local on the Mac unless you explicitly export a report.

The app does not collect:

- browser history
- private browsing state
- cookies
- passwords
- keychain data
- tokens
- secrets
- ambient camera/microphone content

Redaction support is available for:

- usernames
- IP addresses
- MAC addresses
- hostnames
- filesystem paths
- URL secrets

## Supported macOS Releases

The project is developed for current Apple silicon and Intel Macs running modern macOS releases. The codebase is intended to be reviewed and tested on current supported macOS versions from Apple, not on hidden or unsupported system behavior.

## Deployment Modes

### User Monitor Mode

- LaunchAgent under the logged-in user
- Best for UI notifications and per-session alerts
- Default install mode

### System Monitor Mode

- Root-owned LaunchDaemon under `/Library/LaunchDaemons`
- Starts at boot
- Writes to the shared system database
- Does not show GUI alerts directly
- Uses the user notifier companion for visible alerts after login

## Scan Modes

### Safe Scan

The default scan mode is read-only and low impact.

### Verbose Scan

Adds more evidence detail without changing system state.

### Aggressive Local Scan

Targets localhost-only port enumeration and related local checks. This is intentionally opt-in because it can be noisy.

## Evidence Preservation

The platform prefers evidence preservation over cleanup.

Before cleanup or remediation, the app can:

- warn about potential evidence loss
- create an evidence snapshot
- preserve logs, notes, reports, and case data

Do not delete logs automatically during an active investigation.

## Main UI Areas

- Dashboard
- Intrusion Detection
- Investigation Priorities
- Flight Recorder
- Evidence Snapshots
- Apple Security Forecast
- Logs
- Settings
- Operational Health
- Skins
- Results
- Investigation Notes
- Command Preview

## Screenshots

Placeholders for public release:

- Dashboard
- Intrusion Detection
- Investigation Priorities
- Flight Recorder
- Apple Security Forecast
- Operational Health
- Settings

## Installation

### Source

```bash
python3 -m pip install -r requirements.txt
python3 launcher.py
```

### PyInstaller app

Build the bundled macOS app with the provided spec file:

```bash
pyinstaller "Mac Audit Agent.spec"
```

## Uninstall

- Remove the LaunchAgent or LaunchDaemon from Launch Services
- Remove the runtime copy if you installed system mode
- Preserve reports, snapshots, notes, and evidence unless you intentionally choose to remove them

## Legal / Authorized Use Notice

Use this software only on systems and networks you own or are explicitly authorized to assess.

If you are unsure whether you are authorized, stop and obtain written approval before running scans, monitors, or exports.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Privacy](docs/PRIVACY.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Operational Safety](docs/OPERATIONAL_SAFETY.md)
- [Government / Enterprise Evaluation](docs/GOVERNMENT_EVALUATION.md)
- [Public Release Checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Thank you](https://github.com/fuzzlove/macOS-Audit-Agent/blob/main/Thankyou.md)

## Tests

The repository includes unit tests, storage tests, UI smoke tests, and report export tests. The public release checklist requires that the test suite, compile checks, and diff checks pass before distribution.
