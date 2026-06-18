# MSAA Release Readiness

MSAA is release-ready only when the application can prove operational behavior from the UI and tests. A release is blocked if important events only log silently, if health dashboards hide failures, or if production UI contains demo-only or dead controls.

## Required Dashboards

- Alert Pipeline Health must show detector-to-overlay trace state, including the last event stored, notifier consumption, policy decision, cooldown/suppression reason, overlay dispatch result, and DB path mismatch status.
- Monitoring Coverage must show component status for detectors, daemon/notifier, overlay, SQLite, Apple Exposure Assessment, and report export.
- Release Readiness must show pass, needs work, or blocked checks and a 0-100 readiness score.
- Trust Timeline must show trust score changes, deltas, causes, related events, and recommended actions.
- Configuration Drift must show tracked Mac security setting changes with previous/current values and verification guidance.
- Incident Mode must visibly indicate evidence preservation mode and block cleanup unless explicitly confirmed.

## Release Gates

- `pytest` passes.
- `python -m compileall -q mac_audit_agent` passes.
- `python -m build` completes in a clean environment.
- `twine check dist/*` passes.
- `macos-security-audit-agent --verify-clean-install` proves a Python 3.10+ clean virtualenv can install the wheel, import package modules, load bundled assets, run the console command, and emit readiness JSON.
- `macos-security-audit-agent --release-readiness` reports the readiness dashboard as JSON.
- `macos-security-audit-agent --release-readiness-expensive` runs the expensive readiness gates before release.
- The console command is `macos-security-audit-agent`.
- No stale SQLite databases, logs, or generated evidence are bundled.
- No production button is dead, placeholder-only, or demo-only.
- Reports export as JSON, HTML, and SARIF.
- Alert pipeline synthetic event flow passes with visible alert delivery evidence.
- Apple Exposure Assessment works or degrades cleanly without stale/demo cards.

## Alert Pipeline Verification

Run the event-flow verifier from an installed macOS session:

```bash
macos-security-audit-agent --verify-event-flow --monitor-db /Library/Application\ Support/MacAuditAgent/monitor.sqlite3 --no-gui
```

The command prints JSON stage evidence and exits nonzero if any stage is `FAIL`. A daemon-only pass is not sufficient for release readiness: the saved `deployment_event_flow_last_report_json` must include a `visible_alert_delivery` or `overlay_displays_event` stage with status `PASS`, or Alert Pipeline Health must show a successful trace with notifier policy and overlay/dialog delivery evidence.

To verify the visible overlay path directly from the app database:

```bash
macos-security-audit-agent --db ~/.mac_audit_agent.sqlite3 --verify-visible-alert --visible-alert-event-type lid_opened --no-gui
```

This command records a synthetic mandatory event, evaluates alert policy, dispatches through the normal visible-alert overlay path, saves `visible_alert_verification_last_report_json`, and exits nonzero if SQLite storage, policy evaluation, overlay dispatch, or visible delivery fails.

## Clean Install Verification

Run the clean install verifier after building the wheel with Python 3.10 or newer:

```bash
macos-security-audit-agent --db ~/.mac_audit_agent.sqlite3 --verify-clean-install --clean-install-python /path/to/python3.12 --no-gui
```

The command defaults to the newest `dist/*.whl`, creates a temporary virtual environment, installs the wheel, checks imports and bundled assets, runs `macos-security-audit-agent --help`, runs installed release readiness, saves `clean_install_last_report_json`, and exits nonzero if any stage is `FAIL`.

## Manual UI Verification

1. Open Reliability.
2. Refresh Alert Pipeline Health and Monitoring Coverage.
3. Verify Release Readiness has no blocked checks.
4. Enable Incident Mode and confirm cleanup is blocked.
5. Disable Incident Mode.
6. Run a safe scan.
7. Export JSON, HTML, and SARIF reports.
8. Open Apple Exposure Assessment and verify active cards are Mac-focused and current.
9. Open Logs and verify monitor, command, remediation, and app logs are visible without permission failures.

## Blocking Conditions

- Silent high-value alert with no trace explanation.
- Notifier reads a different database path than the detector writes.
- Overlay dispatch failure with no visible UI status.
- Missing privacy, security, license, or uninstall documentation.
- Demo forecast data, placeholder controls, stale logs, or bundled runtime databases.
- Any cleanup path that deletes evidence automatically during Incident Mode.
