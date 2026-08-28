# Python Runtime Compatibility

MSAA selects capabilities by runtime tier instead of assuming the newest `python3` is suitable for every process.

`python3 launcher.py` is a universal, standard-library-only Stage-0 bootstrap command. If the shell's `python3` is Apple Command Line Tools Python 3.9, it validates installed interpreters without importing Qt and re-executes the launcher with a GUI-capable project environment or Python 3.13, 3.12, 3.11, or 3.10. Doctor deliberately remains on Python 3.9. Python 3.14 is not selected for GUI unless the explicit experimental override is enabled.

Use `python3 launcher.py --print-python-selection` to inspect candidates and rejection reasons, or `--no-auto-python` to disable re-exec for debugging. Re-exec depth is bounded and the selected runtime receives the original arguments. The source checkout also provides `scripts/msaa-python3`, which invokes the same universal launcher without fixing a Python minor version.

| Tier | Python | Supported purpose |
| --- | --- | --- |
| A | CPython 3.10–3.13 | Full GUI, notifier, CLI, daemon, integrity, protection, tests and release workflows when feature dependencies exist |
| B | CPython 3.14 and future unvalidated Homebrew versions | Headless doctor, CLI, integrity and protection diagnostics; GUI/notifier blocked by default |
| C | CPython 3.9, including Apple/Command Line Tools Python 3.9.6 | Deprecated doctor/bootstrap diagnostics only; GUI, production services, signing and protection management are unavailable |
| C-doctor | Other unvalidated Apple/system Python builds | Stdlib doctor and bootstrap guidance only |
| D | Python below 3.9, Python 2, broken/nonstandard runtimes | Unsupported; controlled guidance only |

Python 3.14 GUI testing requires `MSAA_ALLOW_EXPERIMENTAL_PY314_GUI=1`. This is not a release-support claim.

## Recommended source setup

```bash
brew install python@3.13
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[gui]"
scripts/msaa gui
```

The launcher selects a project virtual environment first, then Python 3.13, 3.12, 3.11 and 3.10. Headless modes may use Python 3.14. It never installs Homebrew, creates a virtual environment, or installs dependencies automatically.

Python 3.9 lacks several modern `typing` features. MSAA's compatibility shims let doctor mode detect and explain those gaps without requiring `typing_extensions`. Do not install packages named `typing`, `enum`, or other standard-library backports to repair doctor mode. Use Python 3.12 or 3.13 for the GUI; supported active/headless runtimes are Python 3.10–3.14, with Python 3.14 remaining headless-first and GUI-guarded.

On Python 3.9, a successful diagnostic run reports `DOCTOR_ONLY_OK`. Missing office exporters, `nmap`, and inactive PKCS#11 tooling are shown as `OPTIONAL_MISSING` or `INFO`; they do not degrade doctor-only mode. PySide6 may be detected, but dependency presence never overrides the runtime tier and the GUI remains blocked. Runtime topology is skipped by policy rather than treated as a failed inspection. Setup guidance always targets a Python 3.12 or 3.13 project virtual environment and never recommends installing MSAA extras into Apple Command Line Tools Python.

## Minimal and optional dependencies

- `pip install .` — stdlib-oriented core CLI.
- `pip install ".[gui]"` — PySide6 GUI and user notifier.
- `pip install ".[crypto]"` — manifest signature operations; hashing remains available without it.
- `pip install ".[exports]"` — DOCX, XLSX and PDF; HTML/JSON/CSV remain available.
- `pip install ".[network]"` — richer process/network metadata; macOS system tools remain fallbacks.
- `pip install ".[dev]"` — tests and development tools.
- `pip install ".[release]"` — build and publication tooling.

Missing optional dependencies affect only their capabilities. Doctor reports `available`, `degraded`, `unavailable`, or `blocked` with a plain-language fallback.

## System Python

`/usr/bin/python3` may be Apple/Command Line Tools Python without a durable pip/venv contract. MSAA uses it only for doctor/bootstrap guidance even when third-party packages happen to be visible. Do not install packages into Apple-managed locations.

## Active Protection

The daemon prefers the project environment, then Python 3.13 through 3.10, and only then validated headless Python 3.14. The user notifier requires GUI-capable Python 3.10–3.13. Installer evidence records both selected paths and tiers.

## Troubleshooting

```bash
python3 -m mac_audit_agent --doctor --json
scripts/msaa doctor --json
scripts/msaa gui
python3.14 -m mac_audit_agent.protection doctor --json
```
