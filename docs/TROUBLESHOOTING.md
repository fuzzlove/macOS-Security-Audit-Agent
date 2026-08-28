# Troubleshooting

- Run `python3 launcher.py --doctor` or packaged `Mac Audit Agent --doctor --json`.
- Run `python3 launcher.py --print-python-selection` for interpreter selection.
- If GUI preflight fails, use Python 3.12/3.13 or the matching packaged app; never use sudo for GUI.
- Rosetta warnings mean the process architecture differs from native hardware.
- Missing Full Disk Access limits protected paths; MSAA never edits TCC directly.
- Missing Endpoint Security sensor/entitlement means observation-only mode.
- Remove LaunchAgents/Daemons only through the reviewed uninstall workflow; collect diagnostic reports first.
# GUI startup is blocked before opening a window

Run `python3 launcher.py --gui-preflight-json`. `GUI001_UNSUPPORTED_PYTHON` means the selected interpreter is doctor/headless-only; use `python3.12 launcher.py` or `python3.13 launcher.py`. `GUI002` through `GUI010` identify session, privilege, parent-process, dependency, probe, initialization, thread, or AppKit-context failures. Do not retry with `sudo` and do not force the Cocoa platform plugin from SSH, a LaunchDaemon, Codex, or CI. See `docs/gui_runtime_support_matrix.md` and `docs/codex_gui_test_policy.md`.
