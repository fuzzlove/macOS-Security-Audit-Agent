# PyPI Release Checklist

Package: `macos-security-audit-agent`

Product: macOS Security Audit Agent

## Metadata

- [x] `pyproject.toml` exists and uses PEP 621 `[project]` metadata.
- [x] Package name is `macos-security-audit-agent`.
- [x] Console script is `macos-security-audit-agent`.
- [x] Version is PEP 440-compatible.
- [x] README is configured as the PyPI long description.
- [x] LICENSE exists and is included in distributions.
- [x] Project URLs point to the public GitHub repository.

## Included Resources

- [x] Package logos are included under `mac_audit_agent/assets`.
- [x] App icon is included under `mac_audit_agent/assets`.
- [x] Source distribution includes top-level logos.
- [x] Source distribution includes `icon.iconset`.
- [x] Source distribution includes Markdown docs.
- [x] Report HTML and CSS are generated from bundled Python resources.
- [x] No external HTML/CSS template files are required by the current report renderer.

## Production UI

- [x] Product title is `macOS Security Audit Agent`.
- [x] Placeholder screenshot section removed from README.
- [x] Developer monitor menu actions are hidden unless developer mode is enabled.
- [x] Synthetic monitor test buttons are hidden unless developer mode is enabled.
- [x] Lockdown simulation workflow buttons are hidden unless developer mode is enabled.
- [x] Operational health synthetic event-flow verification is hidden unless developer mode is enabled.
- [x] Forecast report export filters simulated/demo forecast cards.

## CLI

- [x] `macos-security-audit-agent --safe-scan`
- [x] `macos-security-audit-agent --aggressive-scan`
- [x] `macos-security-audit-agent --report report.html`
- [x] `macos-security-audit-agent --system-health`
- [x] `macos-security-audit-agent --release-readiness`
- [x] `macos-security-audit-agent --verify-clean-install --clean-install-python /path/to/python3.12`
- [x] Console script launches help successfully after wheel install.
- [x] HTML report generation works after wheel install.

## Build And Validation

- [x] `python -m compileall -q mac_audit_agent`
- [x] `python -m build`
- [x] `twine check dist/*`
- [x] Clean venv local wheel install verifier passes with Python 3.10 or newer.
- [x] `python_version`, `wheel_exists`, `venv_create`, `wheel_install`, `import_sweep`, `resource_check`, `console_help`, and `release_readiness_cli` stages are all `PASS`.
- [x] Release Readiness dashboard shows `clean wheel install verified` as `pass`.

## Before First Upload

- [ ] Create a PyPI project or publish the first release with trusted publishing or an API token.
- [ ] Re-run `twine check dist/*` immediately before upload.
- [ ] Upload with `twine upload dist/*` or trusted publishing.
- [ ] After upload, verify `pip install macos-security-audit-agent` from a clean venv.
- [ ] Launch `macos-security-audit-agent --help` from the PyPI-installed package.
- [ ] Launch the GUI on a macOS desktop session and verify the startup notice and main window.
- [ ] Run a manual production UI pass confirming developer-only controls remain hidden by default.
