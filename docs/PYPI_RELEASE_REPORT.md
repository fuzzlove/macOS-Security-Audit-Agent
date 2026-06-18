# PyPI Release Report

Generated: 2026-06-08

## Summary

The project has been prepared for a first PyPI release as `macos-security-audit-agent`.

Built artifacts:

- `dist/macos_security_audit_agent-0.1.0-py3-none-any.whl`
- `dist/macos_security_audit_agent-0.1.0.tar.gz`

The local wheel installs into a clean virtual environment, the console script resolves, installed package imports pass, and bundled package assets resolve from `site-packages`.

## Missing Assets

No required runtime package assets were missing.

Verified in the built wheel:

- `mac_audit_agent/assets/logo.png`
- `mac_audit_agent/assets/logo2.png`
- `mac_audit_agent/assets/app_icon.icns`
- console entry point metadata
- package metadata

Verified in the source distribution:

- `README.md`
- `LICENSE`
- `Mac Audit Agent.spec`
- top-level `logo.png`
- top-level `logo2.png`
- `icon.iconset/*.png`
- `docs/*.md`
- `mac_audit_agent/assets/*`

No external HTML templates, report templates, CSS files, `.ui`, or `.qrc` resources are required by the current implementation. Report HTML and CSS are generated from Python code and embedded assets.

## Packaging Issues

Resolved:

- Added PEP 621 `pyproject.toml`.
- Added `MANIFEST.in`.
- Added package data for `mac_audit_agent/assets`.
- Removed the legacy license classifier after setuptools rejected it under modern PEP 639 validation.
- Fixed the source distribution manifest pattern for `Mac Audit Agent.spec`.
- Fixed CLI log output when `--db` points at a temp/custom database.

Remaining:

- Public `pip install macos-security-audit-agent` cannot succeed until the first PyPI release is uploaded. Clean venv result before upload:
  - `ERROR: No matching distribution found for macos-security-audit-agent`

## Broken Imports

Checks run:

- `python3 -m compileall -q mac_audit_agent`
- installed-package import sweep using `pkgutil.walk_packages`

Result:

- All installed `mac_audit_agent` modules imported successfully from the clean virtual environment.
- Focused imports from `site-packages` succeeded for:
  - `mac_audit_agent.app`
  - `mac_audit_agent.cli`
  - `mac_audit_agent.collectors`
  - `mac_audit_agent.reporting`
  - `mac_audit_agent.storage`
  - `mac_audit_agent.ui.main_window`

## UI Issues

Resolved:

- Product title is now `macOS Security Audit Agent`.
- README placeholder screenshot section removed.
- Support link text remains current.
- Developer Mode menu toggle is hidden in normal production config.
- Developer monitor menu actions remain hidden unless developer mode is enabled.
- Synthetic monitor/notifier test buttons remain hidden unless developer mode is enabled.
- Lockdown workflow simulation buttons are hidden unless developer mode is enabled.
- Operational Health synthetic event-flow verification is hidden unless developer mode is enabled.
- Fallback QR helper no longer uses demo naming.

Verification:

- `python3 -m pytest -q mac_audit_agent/tests/test_assets.py mac_audit_agent/tests/test_reporting.py`
- Result: `37 passed`

## Forecast Issues

Resolved or already covered:

- Report export filters simulated/demo forecast cards.
- Cached forecast health path runs from CLI.
- No synthetic forecast records are packaged as static resources.

Observed environment state:

- `--system-health` reported forecast cache status `cached (0 cards)`.

Remaining manual release check:

- Run a live forecast refresh on a production macOS network before publishing final release notes.

## Monitor Issues

Observed environment state from `--system-health`:

- System Monitor: repair recommended in this local environment.
- Detector: degraded because no detector timestamp was present in the temp test database.
- Report Export: degraded for the default user reports directory in the sandboxed command context.

These are environment/deployment states, not packaging blockers. The CLI command handled them without crashing and emitted structured JSON.

Remaining manual release check:

- On a normal macOS desktop session, verify user LaunchAgent and optional system LaunchDaemon install/repair flows outside the packaging sandbox.

## CLI Verification

Added console script:

```bash
macos-security-audit-agent
macos-security-audit-agent --safe-scan
macos-security-audit-agent --aggressive-scan
macos-security-audit-agent --report report.html
macos-security-audit-agent --system-health
```

Verified:

- `python3 -m mac_audit_agent.cli --help`
- clean venv local wheel install
- installed `macos-security-audit-agent --help`
- installed `macos-security-audit-agent --system-health --db /private/tmp/msaa-installed-health.sqlite3`
- installed `macos-security-audit-agent --report /private/tmp/msaa-installed-report.html --db /private/tmp/msaa-installed-report.sqlite3`

Generated report:

- `/private/tmp/msaa-installed-report.html`

## Build Verification

Commands:

```bash
/private/tmp/msaa-build-venv/bin/python -m build
/private/tmp/msaa-build-venv/bin/twine check dist/*
```

Result:

- Build succeeded.
- `twine check` passed for wheel and sdist.

## Clean Virtual Environment Install

Command:

```bash
/private/tmp/msaa-install-venv/bin/python -m pip install dist/macos_security_audit_agent-0.1.0-py3-none-any.whl
```

Result:

- Re-run required with Python 3.10 or newer.
- Current host `/usr/bin/python3` is Python 3.9.6, and the wheel correctly enforces `requires-python >=3.10`.
- A Python 3.9 clean venv rejects the wheel with `requires a different Python: 3.9.6 not in '>=3.10'`.
- Installed console-script, resource, report, and `--release-readiness` checks must be repeated in a Python 3.10+ clean venv before upload.

## PyPI Name Status

Checked with a clean virtual environment:

```bash
pip install macos-security-audit-agent
```

Result before first upload:

- No matching distribution was found.

This is expected until the first release is uploaded. After upload, this command must be rerun and recorded as a final release gate.
