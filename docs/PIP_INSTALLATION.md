# pip Installation

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install macos-security-audit-agent
msaa --doctor
```

Install GUI functionality with `macos-security-audit-agent[gui]`; network, exports, forensics, crypto, build, test, and development extras are independent. `pipx install macos-security-audit-agent` is appropriate for CLI use; inject the GUI extra only when a GUI runtime is needed. Normal installation never requires root.
