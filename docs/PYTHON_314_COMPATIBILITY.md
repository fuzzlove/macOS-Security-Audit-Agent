# Python 3.14 compatibility

MSAA supports standard, GIL-enabled CPython 3.14 on macOS. Free-threaded
`cp314t` is a separate, currently unqualified ABI. The supported source
profiles are core (headless), GUI, Office, desktop (GUI plus Office), test,
development, and build. The frozen desktop is built with CPython 3.14 and does
not use an external interpreter or `PYTHONPATH`.

## Reproducible environment

```sh
python3.14 -m venv .venv-py314
.venv-py314/bin/python -m ensurepip --upgrade
.venv-py314/bin/python -m pip install --upgrade pip setuptools wheel
.venv-py314/bin/python -m pip install -c constraints/macos-py314.txt ".[desktop,dev]"
.venv-py314/bin/python -m pip check
.venv-py314/bin/python -m mac_audit_agent --doctor --json
```

Do not install into a Homebrew-managed global environment. A source service
must use a stable installer-owned environment made by the selected 3.14
interpreter. A frozen service must use the bundled monitor/notifier helper and
must never use `python -m`, Homebrew Python, or `PYTHONPATH`.

## Direct dependency matrix

| Distribution | Import | Selected requirement | Role | Native | cp314 arm64 | cp314t |
|---|---|---|---|---|---|---|
| PySide6 | PySide6 | `>=6.10.1,<6.12` (tested profile 6.11.1) | GUI | yes | required/tested | not qualified |
| shiboken6 | shiboken6 | exactly aligned with PySide6 | GUI | yes | required/tested | not qualified |
| PySide6-Essentials | PySide6 | exactly aligned with PySide6 | GUI | yes | required/tested | not qualified |
| PySide6-Addons | PySide6 | exactly aligned with PySide6 | GUI | yes | required/tested | not qualified |
| python-docx | docx | `>=1.1,<2` | Office | no | required/tested | unqualified |
| openpyxl | openpyxl | `>=3.1,<4` | Office | no | required/tested | unqualified |
| lxml | lxml | resolved transitively | Office | yes | required/tested | unqualified |
| PyInstaller | PyInstaller | `>=6.15,<7` | build | platform tool | required/tested | unqualified |
| pytest | pytest | `>=8.4` | test | no | tested | unqualified |

The complete resolved closure, wheel tags, licenses, installed sizes, resolver
report, imports, and functional results are captured from the clean Python
3.14 build environment as release artifacts; classifiers alone are not used
as compatibility evidence.

## Error policy

`DEP314001` means a required package is missing, `DEP314002` an installed
version is incompatible, `ABI314002` an unqualified free-threaded ABI, and
`THR314001` a duplicate USB observer start. Headless, JSON, service, notifier,
test, smoke, and UAT automation paths write structured output and never show a
blocking startup dialog. Frozen missing-package remediation directs users to
replace the complete bundle and never recommends pip.
