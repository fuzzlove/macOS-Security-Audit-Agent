# macOS Security Audit Agent

Liquidsky Network Security 🔒

Mac Audit Agent is a local-first macOS security auditing app built with Python and PySide6. It focuses on transparent, read-only collection, baseline comparison, review tracking, and a desktop UI that helps an investigator understand what changed and what needs follow-up.

## What It Does

- Runs defensive macOS audits with explicit command previews and collection warnings
- Surfaces findings for ports, users, launch items, files, history indicators, processes, packet captures, and local network devices
- Tracks investigation progress with persistent notes, review states, and audit history
- Compares scans against baseline data to highlight drift and review-needed changes
- Runs an optional user-session Background Monitor through a LaunchAgent, not a daemon
- Exports JSON and HTML reports with embedded branding and optional monitor logs or investigation notes

## Safety Model

- Designed for systems you own or are explicitly authorized to assess
- Read-only and dry-run-first by default
- No exploitation, stealth, evasion, credential harvesting, browser-token dumping, keychain dumping, or packet-content capture in the app logic
- Packet capture snapshots store local metadata only
- Local network discovery does not perform vulnerability probing, credential checks, or exploits
- Background monitoring is optional and user-scoped

## Main UI Areas

- Dashboard
- Scan Categories
- Results
- Investigation Notes
- Background Monitor
- Command Preview

The dashboard includes branded header artwork, a clickable logo that opens the usage guide, security score summary, and quick access buttons for the main scan workflows.

## Current Scan Workflows

- Safe Scan
- Verbose Scan
- Aggressive Local Scan
- Full Localhost Port Scan
- Packet Capture Snapshot
- Local Network Device Discovery
- Aggressive Local Vulnerability Review

### Findings Pipeline

The app keeps findings in a single pipeline:

- Collectors gather evidence and safe command output
- Findings are normalized into the shared `Finding` model
- Baseline comparison is attached to the scan result
- The UI renders findings, review-needed groups, and details
- JSON and HTML reports export the same scan result structure

### Binary Trust Scoring

The process and file pipelines now include binary trust scoring:

- process trust score and summary
- file trust score, trust label, and summary
- UI tables show trust and score
- reports include trust metadata

### Baseline Drift Detection

Baseline comparison now includes drift scoring:

- drift score
- drift label
- drift summary
- high-risk change count

This is used to highlight meaningful change without duplicating the existing baseline comparison pipeline.

## Local Network Discovery

Local Network Discovery uses a Fing-style hybrid discovery model:

- ARP first
- mDNS / Bonjour enrichment
- threaded ping fallback
- reverse DNS and vendor enrichment
- baseline comparison

It identifies devices visible on the local network and shows the best available identity as `Likely Hostname` rather than relying on raw IPs alone.

Device records include:

- IP address
- Likely hostname
- MAC address
- Vendor
- Device type
- Confidence
- Discovery methods
- Review flags
- First seen
- Last seen

The UI shows:

- selected interface
- subnet
- gateway
- scan mode
- discovered host count
- device table
- device details panel
- raw debug output
- baseline changes
- review-needed devices

Unknown devices are not proof of compromise, but should be reviewed.

## Investigation Notes

Investigation Notes are stored locally in SQLite and persist across sessions.

Features:

- Freeform notes editor
- Reviewed checklist
- Finding-linked notes
- Timeline notes
- Auto-save every 30 seconds
- Last saved timestamp
- Progress dashboard
- Export to JSON and HTML

Notes are intentionally local and are only included in reports when you explicitly choose to include them.

## Background Monitor

The Background Monitor is optional and user-scoped. It runs as a LaunchAgent in the user GUI domain and keeps continuous monitoring outside the main app process.

### LaunchAgent Behavior

- Installed under `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist`
- Uses the user GUI domain only
- Runs continuously with `RunAtLoad = true` and `KeepAlive = true`
- Writes stdout and stderr logs under `~/.mac_audit_agent/logs`
- Uses a runtime copy under `~/.mac_audit_agent/runtime` to avoid protected-folder access issues

### Monitor Actions

- Install Monitor
- Start Monitor
- Stop Monitor
- Restart Monitor
- Repair Monitor
- Force Reinstall Monitor
- Uninstall Monitor
- Show Logs
- Test Notification
- Test High Priority Dialog
- Generate Test Event
- Event Priorities

### Monitor Coverage

The monitor records privacy and session indicators such as:

- camera or capture-capable process observations
- lid open/close and display/session transitions
- remote login and screen sharing posture
- suspicious processes
- persistence and high-risk security events

The monitor writes events to SQLite and to local logs, then applies notification policy rules. By default, severe events may alert while normal activity stays silent and still gets logged.

### Monitor Health

The UI health panel shows:

- LaunchAgent installed
- LaunchAgent loaded
- PID alive
- heartbeat freshness
- detector timestamp
- current snapshot keys
- last event
- last error
- log paths

## Reports

The app exports JSON and HTML reports for both scan results and investigation notes.

Report output includes:

- scan metadata
- findings
- baseline comparison
- network discovery results
- process trust scoring
- optional background monitor logs
- optional investigation notes

Reports include the logo branding when the asset is available.

## Branding and Assets

The app uses bundled assets for its logo and report branding.

- Main logo asset: `mac_audit_agent/assets/logo.png`
- Secondary dashboard logo: `mac_audit_agent/assets/logo2.png`
- Asset resolution works from source and PyInstaller builds

## Installation

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install PySide6 pytest
```

## Run

Start the desktop app:

```bash
python3 -m mac_audit_agent.app
```

The default local database is:

```text
~/.mac_audit_agent.sqlite3
```

## Packaging

Include bundled assets when building with PyInstaller:

```bash
pyinstaller --add-data "mac_audit_agent/assets:mac_audit_agent/assets" mac_audit_agent/app.py
```

## Testing

Run the full test suite:

```bash
pytest mac_audit_agent/tests
```

Useful focused runs:

```bash
pytest mac_audit_agent/tests/test_storage.py
pytest mac_audit_agent/tests/test_reporting.py
pytest mac_audit_agent/tests/test_network_discovery.py
pytest mac_audit_agent/tests/test_background_monitor.py
```

## Troubleshooting

- If the Background Monitor shows `ModuleNotFoundError`, reinstall it so the LaunchAgent runs from the runtime copy under `~/.mac_audit_agent/runtime`
- If LaunchAgent bootstrap fails, check the monitor stdout and stderr logs under `~/.mac_audit_agent/logs`
- If network discovery returns no devices, verify the selected interface and confirm the subnet is the one you intended to assess
- If reports look empty, confirm a scan has completed and the current scan result is loaded

## Current Status

The app currently includes:

- scan workflows for ports, users, launch items, files, history, processes, packet capture, local network discovery, and localhost scanning
- investigation notes with progress tracking
- background privacy/session monitoring through a user LaunchAgent
- trust scoring for binaries
- baseline drift detection
- report branding with logo assets
- JSON and HTML export paths for scans, monitor events, and notes
