from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


HOMEBREW_PATHS = (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew"))
HOMEBREW_INSTALL_URL = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
APPROVED_NETWORK_CAPTURE_PACKAGES = {
    "wireshark-cli": ("install", "wireshark"),
    "wireshark-chmodbpf": ("install", "--cask", "wireshark-chmodbpf"),
    "wireshark-app": ("install", "--cask", "wireshark-app"),
}


@dataclass(frozen=True)
class DependencyInstallResult:
    status: str
    executable: str
    arguments: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str

    def to_dict(self) -> dict:
        return asdict(self)


def find_homebrew_binary() -> str | None:
    for candidate in HOMEBREW_PATHS:
        if candidate.is_file() and os.access(candidate, os.X_OK) and not candidate.is_symlink():
            return str(candidate)
    return None


def install_nmap_with_homebrew(
    brew_path: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> DependencyInstallResult:
    approved = Path(brew_path)
    if approved not in HOMEBREW_PATHS or not approved.is_file() or approved.is_symlink():
        raise PermissionError("DEP_INSTALL_PATH_REFUSED: Homebrew must be an executable at an approved fixed path.")
    arguments = ("install", "nmap")
    completed = runner(
        [str(approved), *arguments],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
        shell=False,
    )
    return DependencyInstallResult(
        "installed" if completed.returncode == 0 else "failed",
        str(approved), arguments, completed.returncode,
        (completed.stdout or "")[-65536:], (completed.stderr or "")[-65536:],
    )


def open_homebrew_installer_in_terminal(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> DependencyInstallResult:
    """Open Homebrew's official interactive installer; Terminal owns all password prompts."""
    command = f'/bin/bash -c "$(/usr/bin/curl -fsSL {HOMEBREW_INSTALL_URL})"'
    apple_script = (
        'tell application "Terminal"\n'
        'activate\n'
        f'do script "{command.replace(chr(34), chr(92) + chr(34))}"\n'
        'end tell'
    )
    completed = runner(
        ["/usr/bin/osascript", "-e", apple_script],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        shell=False,
    )
    return DependencyInstallResult(
        "terminal_opened" if completed.returncode == 0 else "failed",
        "/usr/bin/osascript", ("official_homebrew_interactive_installer",), completed.returncode,
        (completed.stdout or "")[-8192:], (completed.stderr or "")[-8192:],
    )


def open_network_capture_install_in_terminal(
    brew_path: str,
    package_id: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> DependencyInstallResult:
    """Open one allowlisted capture-tool install in Terminal for user review."""
    approved = Path(brew_path)
    if approved not in HOMEBREW_PATHS or not approved.is_file() or approved.is_symlink():
        raise PermissionError("DEP_INSTALL_PATH_REFUSED: Homebrew must be an executable at an approved fixed path.")
    arguments = APPROVED_NETWORK_CAPTURE_PACKAGES.get(package_id)
    if arguments is None:
        raise ValueError("DEP_INSTALL_PACKAGE_REFUSED: network capture package is not allowlisted.")
    command = shlex.join((str(approved), *arguments))
    apple_script = (
        'tell application "Terminal"\n'
        'activate\n'
        f'do script "{command.replace(chr(34), chr(92) + chr(34))}"\n'
        'end tell'
    )
    completed = runner(
        ["/usr/bin/osascript", "-e", apple_script], capture_output=True, text=True,
        timeout=15, check=False, shell=False,
    )
    return DependencyInstallResult(
        "terminal_opened" if completed.returncode == 0 else "failed",
        str(approved), tuple(arguments), completed.returncode,
        (completed.stdout or "")[-8192:], (completed.stderr or "")[-8192:],
    )


__all__ = [
    "APPROVED_NETWORK_CAPTURE_PACKAGES", "DependencyInstallResult", "HOMEBREW_INSTALL_URL", "find_homebrew_binary",
    "install_nmap_with_homebrew", "open_homebrew_installer_in_terminal", "open_network_capture_install_in_terminal",
]
