# GUI Runtime Support Matrix

| Context | Policy |
|---|---|
| Python 3.9 | Doctor and limited diagnostics only; GUI001 before Qt import |
| Python 3.10 or 3.11 | GUI unsupported until explicitly validated |
| Python 3.12 | Supported GUI runtime after session and dependency preflight |
| Python 3.13 | Supported GUI runtime after session and dependency preflight |
| Python 3.14 or future versions | GUI unsupported until explicitly validated |
| Root or LaunchDaemon | GUI forbidden; use headless privileged helper |
| SSH or no Aqua session | GUI forbidden |
| Codex/CI | Explicit `offscreen`, `minimal`, or confirmed `interactive-aqua` harness required |
| Signed application bundle | Supported only with packaged runtime, consistent Qt tree, valid signing, and LaunchServices context |

Recommended source environment:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
PYTHONNOUSERSITE=1 python launcher.py
```

The repository does not yet contain a reviewed deterministic `requirements.lock`; release engineering must generate and approve it before using the exact command above.

Use `python3 launcher.py --doctor` for Python 3.9 diagnostics and `python3 launcher.py --gui-preflight-json` for static machine-readable GUI assessment. Neither initializes Qt.
