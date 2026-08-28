from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import mac_audit_agent.dependency_installer as installer


def test_homebrew_detection_uses_only_approved_fixed_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    brew = tmp_path / "brew"
    brew.write_text("fixture", encoding="utf-8")
    brew.chmod(0o755)
    monkeypatch.setattr(installer, "HOMEBREW_PATHS", (brew,))

    assert installer.find_homebrew_binary() == str(brew)


def test_nmap_install_uses_fixed_argv_without_shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    brew = tmp_path / "brew"
    brew.write_text("fixture", encoding="utf-8")
    brew.chmod(0o755)
    monkeypatch.setattr(installer, "HOMEBREW_PATHS", (brew,))
    observed = {}

    def runner(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(arguments, 0, "installed", "")

    result = installer.install_nmap_with_homebrew(str(brew), runner=runner)

    assert result.status == "installed"
    assert observed["arguments"] == [str(brew), "install", "nmap"]
    assert observed["kwargs"]["shell"] is False


def test_unapproved_brew_path_is_rejected(tmp_path: Path) -> None:
    brew = tmp_path / "brew"
    brew.write_text("fixture", encoding="utf-8")

    with pytest.raises(PermissionError, match="approved fixed path"):
        installer.install_nmap_with_homebrew(str(brew))


def test_homebrew_bootstrap_opens_official_installer_in_terminal() -> None:
    observed = {}

    def runner(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(arguments, 0, "tab 1", "")

    result = installer.open_homebrew_installer_in_terminal(runner=runner)

    assert result.status == "terminal_opened"
    assert observed["arguments"][0] == "/usr/bin/osascript"
    assert installer.HOMEBREW_INSTALL_URL in observed["arguments"][2]
    assert observed["kwargs"]["shell"] is False
