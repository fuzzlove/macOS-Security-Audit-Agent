from pathlib import Path

ROOT=Path(__file__).parents[2]

def test_zsh_and_bash_pre_submission_contracts_are_present():
    zsh=(ROOT/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh").read_text()
    bash=(ROOT/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.bash").read_text()
    assert "bracketed-paste" in zsh and "accept-line" in zsh and "REPLY=error" in zsh
    assert "READLINE_LINE" in bash and "coverage_degraded" in bash and "DEBUG" not in bash
    assert "eval " not in zsh and "eval " not in bash

def test_terminal_emulators_are_telemetry_not_enforcement_dependencies():
    zsh=(ROOT/"mac_audit_agent/clickfix/shell_integration/msaa-clickfix.zsh").read_text()
    for product in ("Terminal.app","iTerm2","Warp","Visual Studio Code","Cursor"): assert product not in zsh
