# macOS Security Audit Agent (MSAA)

MSAA is a local-first macOS audit, monitoring, and investigation platform. It is designed for analysts who need transparent evidence collection, reviewable alerts, and local-only reports without sending telemetry off the machine.

This repository is intended to be understandable, auditable, and safe enough for public review, institutional evaluation, and responsible internal deployment.

Add/Remove Programs now includes dependency-aware system application containment. See [System Application Control](docs/SYSTEM_APPLICATION_CONTROL.md) for the reversible quarantine boundary, administrator-authorization requirements, and sealed-system limitations.

Zero Trust automatic and manual control verification is documented in [Zero Trust Endpoint Validation](docs/ZERO_TRUST_ENDPOINT_VALIDATION.md), including evidence-state auditing and client validation of network scope.

The [Security Research Device guide](docs/SECURITY_RESEARCH_DEVICE.md) documents the proportional macOS hardening wizard, its read-only checks, manual evidence workflow, source policy, and the important distinction between assessment support and certification or government authorization.

Engagement and network-assurance workflows:

- [Consultant Timesheet](docs/CONSULTANT_TIMESHEET.md)
- [DNS Configuration Assurance](docs/DNS_CONFIGURATION_ASSURANCE.md)
- [Network Segmentation and authorized egress validation](docs/NETWORK_SEGMENTATION.md)
- [ARIN and RIPE RDAP Lookup](docs/NETWORK_RDAP_LOOKUP.md)
- [UI Functionality and Help Audit](docs/UI_FUNCTIONALITY_AND_HELP_AUDIT.md)

The [MSAA ClickFix Shell Guard](docs/clickfix-shell/README.md) provides local pre-submission inspection for instrumented zsh/Bash sessions and an opt-in shell-agnostic PTY proxy. It defaults to audit mode, records no raw command text, and complements—not replaces—endpoint, browser, network, and user-awareness controls.

The [ClickFix adversarial validation corpus](docs/CLICKFIX_TEST_CORPUS.md) exercises inert network-to-interpreter, decoding, obfuscation, staging, AppleScript, persistence, security-bypass, destructive-symbolic, credential-intent, drive-by-context, chain-correlation, and benign-control fixtures without executing them or opening network connections. Measured results and environment limitations are recorded in the [coverage matrix](docs/CLICKFIX_COVERAGE_MATRIX.md).

The native assurance foundation in `native/MSAAAssurance` evaluates configuration,
operation, observability, validation, and recovery independently; creates
deterministic chained evidence; exports signed offline-verifiable bundles; and
includes an unprivileged SwiftUI shell plus `msaa-verify`. It does not claim
certification or that a passing control proves absence of compromise.

## Python quick start

The full GUI is validated on CPython 3.10–3.13. Python 3.14 is headless-only by default, and Apple/system Python is doctor/bootstrap-only. Use `scripts/msaa doctor --json` or `scripts/msaa gui` to select a suitable installed interpreter. Minimal CLI installation is `python -m pip install -e .`; add only the needed extras: `.[gui]`, `.[crypto]`, `.[exports]`, `.[network]`, `.[dev]`, or `.[release]`. Missing extras degrade individual features instead of disabling MSAA. See [Python Runtime Compatibility](docs/PYTHON_RUNTIME_COMPATIBILITY.md).

MSAA is an independent project by Liquidsky Network Security. References to NIST, CISA, DoD, NSA, PCI SSC, MITRE, or other standards bodies are for standards mapping, source attribution, and public guidance alignment only. They do not imply endorsement, sponsorship, certification, or approval.

## Mission and authorized use

MSAA defaults to advisory operation. A license, EULA acceptance, NDA, role, developer/debug mode, affiliation, emergency assertion, or user statement does not authorize access to a target. Operational use requires a current scoped authorization context and designated human approvals. The GUI presents the draft authorized-use EULA on every launch.

MSAA now includes a signed product-licensing service for offline license import
and Stripe Checkout/HTTPS activation. It uses webhook-confirmed fulfillment and
local Ed25519 verification, keeps Stripe credentials and issuer private keys
outside the application, and preserves core protection and evidence when
commercial activation is unavailable. See [Product Licensing](docs/PRODUCT_LICENSING.md)
and [Stripe Licensing and Distribution](docs/STRIPE_LICENSING.md).

Without a valid signed license, the GUI runs in Demo Preview: users can
navigate and read the product—including awareness presentations—but operational
controls remain disabled until a license is purchased/activated or imported.

Review [Mission](docs/MISSION.md), [AI Governance](docs/AI_GOVERNANCE.md), [Draft EULA](docs/EULA.md), [Authorization](docs/AUTHORIZATION.md), and [Implementation Notes](docs/IMPLEMENTATION_NOTES.md) before deployment. These controls are designed to support governance and require legal, privacy, security, system-owner, and authorizing-official review; they do not establish compliance or government approval.

On first use by each local macOS user, MSAA requires the [basic Computer Science Ethics class](docs/COMPUTER_SCIENCE_ETHICS.md) and assessment before presenting the EULA. A passing record is cached locally and logged once; the EULA remains mandatory on every application launch.

## What It Does

- Runs read-only macOS security audits
- Surfaces findings with evidence, confidence, and rule provenance
- Tracks review state, notes, suppression decisions, and case history
- Correlates events into investigation patterns and flight-recorder timelines
- Provides [Behavioral Telemetry](docs/BEHAVIORAL_TELEMETRY.md) with local host/user baselines, coverage-aware anomaly explanations, bounded aggregation, and privacy-minimized evidence references
- Provides Apple Exposure Assessment summaries with low-noise grouping
- Supports optional user LaunchAgent mode and optional root-owned system LaunchDaemon mode
- Exports HTML and JSON reports locally
- Preserves evidence snapshots before cleanup or remediation
- Runs a high-sensitivity, monitor-only RCE behavior and approved local CVE-exposure subsystem inside the existing macOS LaunchDaemon; polling mode is explicitly degraded without Endpoint Security entitlement
- Provides Persistence Intelligence for read-only macOS persistence inventory, scoring, baselines, chain view, timeline, coverage, and reports


## What It Does Not Do

- No off-device product analytics or telemetry upload; security telemetry remains local unless explicitly exported
- No cloud dependency
- No browser history extraction
- No cookie, token, password, or keychain extraction
- No hidden persistence
- No stealth behavior
- No offensive exploitation
- No hack-back or retaliation
- No automatic destructive cleanup
- No exploit execution, automatic RCE confirmation, or autonomous false-positive disposition
- No remediation without user approval

## Safety Model

The default mode is conservative.

Safe by default:

- no packet capture unless explicitly chosen
- no aggressive scans unless explicitly chosen
- no full localhost scan unless explicitly chosen
- no destructive cleanup by default

## RCE monitor

The [RCE monitor](docs/RCE_MONITOR.md) preserves qualifying runtime behavior for human review, keeps vulnerability exposure distinct from exploitation, validates CVE identifiers against an approved offline store, and reports telemetry gaps. See the [event schema](docs/RCE_EVENT_SCHEMA.md), [CVE data contract](docs/RCE_CVE_DATA.md), [review workflow](docs/RCE_FALSE_POSITIVE_REVIEW.md), [configuration](docs/RCE_MONITOR_CONFIGURATION.md), and [troubleshooting](docs/RCE_MONITOR_TROUBLESHOOTING.md).

Its [macOS process-injection layer](docs/MACOS_PROCESS_INJECTION.md) classifies supported dyld, Mach, ptrace, exception-port, thread-state, and memory-image patterns, while preserving uncertain combinations under stable investigation identifiers.

The expanded [Process Injection Monitor](docs/PROCESS_INJECTION_MONITOR.md) adds platform-neutral primitives, stable boot/start process identity, behavior graphs, partial/variant/novel lineage, reviewed benign context, evidence bundles, and `msaa process-injection` analyst workflows.
- no system daemon install by default
- no remediation execution by default
- no automatic uploads
- no automatic cloud enrichment using private data

Important features that can increase risk always require explicit user action and a warning.

## Resource Management

MSAA is designed to run with bounded resource usage on average Macs. Heavy scans, Apple/CVE lookups, framework source refreshes, and report exports should use cache-first refresh, timeouts, output caps, and the shared resource budget profiles: Low Resource, Balanced, and Thorough. GUI startup blocks unsupported Python/Qt runtime paths such as Python 3.14 until validated.

See:

- `docs/PERFORMANCE_AND_RESOURCE_MANAGEMENT.md`
- `docs/API_REFRESH_POLICY.md`
- `docs/MACOS_RUNTIME_COMPATIBILITY.md`
- `docs/SHUTDOWN_BEHAVIOR.md`

## Privacy Model

Security telemetry and operational evidence stay local on the Mac unless you
explicitly export a report. If you explicitly start online license checkout,
MSAA sends a pseudonymous installation fingerprint and bounded transaction
metadata to the licensing service, while payment details are entered directly
into Stripe-hosted Checkout. Offline licensing remains available. See
[Privacy](docs/PRIVACY.md) and [Stripe Licensing](docs/STRIPE_LICENSING.md).

Collection, access, export, retention, sharing, and AI-processing decisions are governed by the fail-closed classification framework described in [Data Governance](docs/DATA_GOVERNANCE.md). An explicit export request is not by itself sufficient for restricted data: role, approval, destination, and protection evidence are also evaluated.

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

## Release Integrity

Final releases can be protected with a canonical signed integrity manifest and signed `dist/` artifact manifests. Development and Pre-UAT integrity use the trusted developer-machine signing workflow.

MSAA also includes a DoD-aligned, tamper-evident source integrity manifest for developer/build workflows. Authorized rehashing is explicit and audited:

```bash
python3.12 -m mac_audit_agent.integrity machine enroll \
  --developer "Liquidsky Network Security" \
  --organization "Liquidsky Network Security" \
  --machine-label "Liquidsky Primary Dev Mac"
python3.12 -m mac_audit_agent.integrity sign \
  --policy dev \
  --developer-machine \
  --author "Liquidsky Network Security" \
  --reason "approved development baseline" \
  --build-id "$BUILD_ID"
python3.12 -m mac_audit_agent.integrity verify --policy dev --strict
python3.12 -m mac_audit_agent.integrity status --policy dev --verbose
```

This control uses SHA-256 and developer-machine P-256 signatures. It is not a claim of formal DoD certification or compliance, and it does not replace future executable signing and notarization.

Start with:

```bash
python3 -m mac_audit_agent.integrity.release_sign all --version 1.0b --mode public_release
python3 -m mac_audit_agent.integrity.release_verify --strict
```

Never commit the private release signing key. See `docs/INTEGRITY_RELEASE_SIGNING.md` and `docs/RELEASE_PROCESS.md`.

## Scan Modes

### Safe Scan

The default scan mode is read-only and low impact.

### Verbose Scan

Adds more evidence detail without changing system state.

### Aggressive Local Scan

Targets localhost-only port enumeration and related local checks. This is intentionally opt-in because it can be noisy.

TCP/UDP scan functionality can optionally use Nmap as an external scanning engine. Nmap is a separate open-source project maintained by the Nmap Project. MSAA invokes Nmap locally as a wrapper when available.

https://nmap.org/

## Acknowledgements

MSAA Persistence Intelligence incorporates concepts and, where compatible, implementation ideas from macOS Persistence Radar, an open-source macOS persistence visibility and audit project.

https://github.com/fuzzlove/macOS-Persistence-Radar

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
- Apple Exposure Assessment
- Default Credential Scanner (Network section; explicit authorized HTTP(S) targets only)
- Logs
- Settings
- Operational Health
- Skins
- Results
- Investigation Notes
- Command Preview

## Installation

MSAA supports Python 3.10, 3.11, 3.12, and 3.13. Python 3.14 is not yet supported for the Qt GUI. A Python interpreter is the program that runs Python code; a virtual environment is an isolated folder that keeps this project's packages separate from the rest of your computer.

Check the selected interpreter before installing:

```bash
python3 --version
python3 -c "import sys; print(sys.executable)"
```

On Windows, use `py -3.13` where the examples use `python3.13`. On macOS or Linux, use the versioned command installed on your machine, such as `python3.12` or `python3.13`.

### Create an isolated environment

```bash
python3.13 -m venv .venv
```

Activate it:

- macOS or Linux: `source .venv/bin/activate`
- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- Windows Command Prompt: `.venv\Scripts\activate.bat`

After activation, `python` means the isolated interpreter. Upgrade its installer and verify its location:

```bash
python -m pip install --upgrade pip
python -c "import sys; print(sys.executable)"
```

Do not use `sudo pip` or an administrator shell for normal installation.

### Install from PyPI

```bash
python -m pip install "macos-security-audit-agent[gui]"
python -m mac_audit_agent --doctor
macos-security-audit-agent
```

The standard package provides headless/bootstrap diagnostics. Extras add optional features:

```bash
python -m pip install "macos-security-audit-agent[gui]"     # macOS desktop UI
python -m pip install "macos-security-audit-agent[office]"  # Word and Excel exports
python -m pip install "macos-security-audit-agent[all]"     # all user features
python -m pip install "macos-security-audit-agent[dev]"     # contributor tools
```

CLI examples:

```bash
macos-security-audit-agent --safe-scan
macos-security-audit-agent --aggressive-scan
macos-security-audit-agent --report report.html
macos-security-audit-agent --system-health
macos-security-audit-agent --release-readiness
```

### GitHub

Install directly from the GitHub repository:

```bash
python -m pip install "macos-security-audit-agent[gui] @ git+https://github.com/fuzzlove/macOS-Security-Audit-Agent.git"
macos-security-audit-agent
```

### Local Source

Clone the repository and install it locally:

```bash
git clone https://github.com/fuzzlove/macOS-Security-Audit-Agent.git
cd macOS-Security-Audit-Agent
python -m pip install -e ".[all,dev]"
python -m mac_audit_agent --doctor
```

For a recommended local desktop installation and the source launcher:

```bash
python -m pip install -r requirements.txt
python launcher.py
```

For a lightweight CLI/doctor-only installation, use
`python -m pip install -r requirements-core.txt`. Contributor tooling is in
`requirements-dev.txt`, and reproducible app-build tooling is in
`requirements-build.txt`.

### PyInstaller app

Build the recommended one-directory macOS app with the maintained spec, or explicitly build the slower one-file variant:

```bash
python -m pip install ".[all,build]"
python scripts/build_pyinstaller.py --format onedir --clean
python scripts/build_pyinstaller.py --format onefile --clean
```

The frozen `.app` contains Python and its dependencies; end users do not install Python or run pip. If a frozen application reports `PKG001`, reinstall the correct macOS/CPU build instead of installing packages into the bundle. See [Packaging](docs/PACKAGING.md).

### Diagnostics and troubleshooting

Run either human-readable or JSON diagnostics:

```bash
python -m mac_audit_agent --doctor
python -m mac_audit_agent --doctor --json
```

The doctor reports the interpreter, virtual environment, OS/architecture, optional packages, external tools, resources, writable locations, and frozen state. It never tests the network during startup and redacts home-directory prefixes and secret-like MSAA environment variables.

Common fixes:

- `python is not recognized`: install Python from python.org, reopen the terminal, then use `py -3.13 -m venv .venv`.
- `python3 is not found`: install Python 3.10–3.13, then use its versioned command to create `.venv`.
- `No module named ...`: activate `.venv`, confirm `python -c "import sys; print(sys.executable)"`, then run `python -m pip install ".[all]"`.
- Package installed into another interpreter: always replace bare `pip` with `"<the-python-path>" -m pip`; the doctor shows the exact path.
- pip unavailable: run `python -m ensurepip --upgrade`, then `python -m pip install --upgrade pip`.
- Unsupported Python: install Python 3.10–3.13 and recreate the virtual environment. Environments cannot change their Python version in place.
- Dependency conflict: create a fresh `.venv`; do not force incompatible global packages together.
- Compiler/build-tools error: prefer a published wheel. On macOS install Xcode Command Line Tools only when a dependency genuinely needs compilation.
- Missing DLL/shared library or wrong architecture: recreate the environment with a Python build matching the OS and CPU; do not copy native libraries manually.
- Permission denied or an externally managed Python environment: install inside `.venv`, not globally and not with administrator/root privileges.
- Proxy/TLS failure: verify the organization proxy and CA settings; do not disable TLS verification. Offline installs require pre-downloaded wheels for the same Python/OS/CPU.
- Antivirus/quarantine warning for a frozen app: verify the release source and signature, restore only a trusted build, or download it again.
- Incorrect frozen build: Apple silicon requires `arm64`; Intel requires `x86_64`. PyInstaller builds are made on the target OS and are not cross-platform.

Deactivate the environment when finished:

```bash
deactivate
```

See [Compatibility review](docs/COMPATIBILITY_REVIEW.md) for error codes and limitations.

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
- [Data Governance](docs/DATA_GOVERNANCE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Operational Safety](docs/OPERATIONAL_SAFETY.md)
- [Government / Enterprise Evaluation](docs/GOVERNMENT_EVALUATION.md)
- [Public Release Checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Thank you](https://github.com/fuzzlove/macOS-Security-Audit-Agent/blob/main/Thankyou.md)

## Tests

The repository includes unit tests, storage tests, UI smoke tests, and report export tests. The public release checklist requires that the test suite, compile checks, and diff checks pass before distribution.
