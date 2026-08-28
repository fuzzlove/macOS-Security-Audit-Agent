# Compatibility and Reliability Review

## Support decision

MSAA source and GUI metadata support standard GIL-enabled CPython 3.10 through 3.14. Python 3.14 qualification uses PySide6 6.11.1 and PyInstaller 6.21.0; free-threaded `cp314t` remains a separate unqualified ABI.

The security collectors and desktop UI are macOS-specific. The dependency-free bootstrap, package installation, and environment doctor are portable so Windows and Linux users receive an explanation instead of an import traceback. Those systems are not claimed as supported security-collection targets.

Python 3.14.6 was exercised locally for dependency resolution, Qt startup/shutdown, Office exports, wheel/sdist clean installs, focused tests, and PyInstaller builds. Older-version results remain separate evidence and cannot satisfy the Python 3.14 release gate.

## Repository audit

- Entry points: `launcher.py`, `python -m mac_audit_agent`, `macos-security-audit-agent`, the GUI script, `mac_audit_agent.cli`, and `python -m mac_audit_agent.integrity`.
- Layout: one setuptools package with UI, collectors, integrity tooling, persistence/network intelligence, runtime helpers, exporters, quality checks, and tests.
- Dependency authority: `pyproject.toml`. `requirements.txt` is only an editable contributor wrapper and contains no duplicated versions.
- Core dependency: Python standard library only for bootstrap and diagnostics.
- Optional dependencies: PySide6 (`gui`); openpyxl and python-docx/import name `docx` (`office`). `all`, `dev`, and `build` compose user and contributor workflows.
- Native dependencies: PySide6/shiboken6 and Qt frameworks. Their wheel must match Python, macOS, and CPU architecture.
- Build/test tools: pytest, Ruff, build, Twine, and PyInstaller.
- Dynamic imports: optional office exporters; the legacy `frameworks.py` sibling loaded by `frameworks/__init__.py`; integrity CLI dispatch. The legacy sibling must be explicit PyInstaller data.
- External commands: macOS tools including `launchctl`, `codesign`, `security`, `system_profiler`, `ioreg`, `diskutil`, `lsof`, `netstat`, and optional `nmap`; integrity workflows also use Git, OpenSSL, ykman, and pkcs11-tool. Feature code generally uses argument arrays and bounded timeouts. Doctor reports the cross-feature optional tools without treating them as startup requirements.
- Network behavior: standard-library HTTP clients are used for opt-in Apple/CVE/source refresh operations. Startup and doctor make no network request.
- Resources: PNG/JSON/icon assets and integrity JSON/public-key material. Resource lookup supports source, wheel, one-directory, and `_MEIPASS` extraction layouts.
- Writable state: per-user application data, cache, log, SQLite database, reports/snapshots, and the system temporary directory. System LaunchDaemon mode additionally requires explicitly authorized `/Library` writes.
- Environment variables: `MSAA_*` runtime, integrity, signing, policy, GUI, and release controls; `YKCS11`; standard XDG and platform location variables. Doctor reports only secret-like MSAA variable names and replaces values with `<redacted>`.
- Configuration: defaults are typed in code and operational state is persisted in SQLite. There is no standalone user configuration file to corrupt or reset; therefore file-replacement recovery is not applicable.
- CI: portable bootstrap tests across macOS, Windows, and Linux on Python 3.10/3.12/3.13; full macOS tests on every supported minor; package and PyInstaller smoke jobs on macOS.

## Risks found and changes made

Previously the console entry imported the GUI before parsing arguments, so missing PySide6 broke help and headless operations. It now lazy-loads the GUI, while a small Python-3.8-parseable bootstrap checks the supported version before importing application modules.

Previously dependencies were duplicated and contradictory: wheel metadata declared three packages while `requirements.txt` declared eight additional unused packages plus test/build tools. Metadata is now canonical and office/GUI packages are optional extras.

Previously the PyInstaller spec copied the complete source package, tests, docs, and caches as data in addition to analyzed Python modules. Data collection is now limited to runtime resources and the one genuinely filename-loaded module.

Startup failures now use a common message and append JSON Lines records with full tracebacks to a writable diagnostic log. Full tracebacks appear to the user only with `--debug`. Frozen failures recommend reinstalling the correct bundle, never pip installation.

The doctor now verifies `VIRTUAL_ENV` against `sys.prefix`, preserves the invoked `sys.executable` rather than resolving away a virtual-environment shim, reports pip availability, and probes optional external-tool versions with three-second timeouts. This identifies the common “installed into a different Python” failure directly.

Two structurally unbounded memory paths were corrected: the USB reconnect observer now uses a bounded queue with backpressure rather than dropping security events, and shared URL byte retrieval rejects responses above a 10 MiB default safety limit with `NET001`. Existing resource-budget worker pools were already bounded to one through three workers depending on profile.

## Stable startup error codes

- `PY001`: unsupported Python
- `DEP001`: missing Python dependency
- `DEP002`: incompatible dependency version (doctor classification)
- `DEP003`: installed package failed during import
- `SYS001`: native library or architecture load failure
- `SYS002`: required external executable missing (feature boundary)
- `SYS003`: unsupported operating system for GUI/security collection
- `RES001`: required packaged resource missing
- `CFG001`: invalid configuration
- `FS001`: permission or writable-location failure
- `NET001`: network unavailable/timeout at an opt-in network boundary
- `MEM001`: memory allocation failure
- `PKG001`: incomplete or incompatible frozen application
- `APP999`: unexpected boundary failure

Not every feature-specific subsystem has yet migrated its historical messages to these codes. The application boundary and doctor are centralized; existing feature return models were preserved to avoid changing public APIs.

## Remaining limitations

- Only macOS is a supported collection and GUI target.
- Optional external tools expose different output across macOS releases; their individual collectors remain responsible for parsing/version semantics.
- PySide6 is intentionally not imported by headless doctor/help paths, but many operational CLI commands share GUI-adjacent modules and therefore still require the `gui` extra in the current architecture.
- A full test-suite run has known pre-existing strict-integrity failures and long-running tests; compatibility smoke and tamper-resistance tests are separately enforced.
- The bootstrap cannot prevent a syntax error on Python versions too old to parse Python's standard library or package import machinery. It is deliberately conservative and parseable on Python 3.8+.
