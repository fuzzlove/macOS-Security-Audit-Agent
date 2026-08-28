from __future__ import annotations

import json
import os
import shlex
import subprocess
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

TERMINAL_EXECUTABLE = Path("/usr/bin/osascript")
MAX_INSTALL_PATH_BYTES = 4096


class DevelopmentSensorLaunchError(RuntimeError):
    """Raised when the reviewed Terminal installation cannot be launched safely."""


@dataclass(frozen=True)
class TerminalInstallLaunch:
    launched: bool
    command: str
    event_id: str
    message: str


def repository_install_command(repository_root: Path | None = None) -> str:
    """Return a copyable, fixed-argument development installer command.

    Paths are shell-quoted because the command is deliberately shown to the user
    and executed by Terminal, never by the MSAA GUI process.
    """
    root = (repository_root or Path(__file__).resolve().parents[2]).resolve()
    python = root / ".venv" / "bin" / "python"
    launcher = root / "launcher.py"
    for value in (root, python, launcher):
        encoded = os.fsencode(value)
        if len(encoded) > MAX_INSTALL_PATH_BYTES or any(byte < 32 for byte in encoded):
            raise DevelopmentSensorLaunchError("The installation path contains unsupported control characters or exceeds the safe length limit.")
    if not python.is_file() or not launcher.is_file():
        raise DevelopmentSensorLaunchError(
            "The source-development installer is unavailable. Create the project virtual environment and verify launcher.py first."
        )
    return (
        f"cd -- {shlex.quote(str(root))} && "
        f"sudo -- {shlex.quote(str(python))} {shlex.quote(str(launcher))} "
        "--install-protection-services --developer-mode --allow-unsigned-development-runtime"
    )


def repository_repair_command(repository_root: Path | None = None) -> str:
    """Return the fixed service-repair command for a source installation."""
    root = (repository_root or Path(__file__).resolve().parents[2]).resolve()
    python = root / ".venv" / "bin" / "python"
    launcher = root / "launcher.py"
    for value in (root, python, launcher):
        encoded = os.fsencode(value)
        if len(encoded) > MAX_INSTALL_PATH_BYTES or any(byte < 32 for byte in encoded):
            raise DevelopmentSensorLaunchError(
                "The repair path contains unsupported control characters or exceeds the safe length limit."
            )
    if not python.is_file() or not launcher.is_file():
        raise DevelopmentSensorLaunchError(
            "The source-development repair command is unavailable. Create the project virtual environment and verify launcher.py first."
        )
    return (
        f"cd -- {shlex.quote(str(root))} && "
        f"sudo -- {shlex.quote(str(python))} {shlex.quote(str(launcher))} "
        "--repair-protection-services --developer-mode --allow-unsigned-development-runtime"
    )


def _apple_script_string(value: str) -> str:
    if any(ord(character) < 32 for character in value):
        raise DevelopmentSensorLaunchError("The generated command contains an unsupported control character.")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _write_launch_event(
    event_id: str,
    *,
    outcome: str,
    audit_path: Path | None = None,
    event_type: str = "RANSOMWARE_DEVELOPMENT_SENSOR_INSTALL_LAUNCH",
) -> None:
    path = audit_path or (Path.home() / "Library/Application Support/MSAA/AntiRansomware/audit/sensor-install.jsonl")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    event = {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "outcome": outcome,
        "administrator_approval_requested": True,
        "password_collected_by_msaa": False,
        "raw_command_recorded": False,
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)


def endpoint_security_sensor_repair_command(repository_root: Path | None = None) -> str:
    """Return the fixed command that verifies, installs, and starts the ES sensor."""
    root = (repository_root or Path(__file__).resolve().parents[2]).resolve()
    installer = root / "scripts" / "install_development_endpoint_security_sensor.sh"
    verifier = root / "scripts" / "verify_endpoint_security_signature.sh"
    bundle = root / "dist" / "active-containment" / "MSAAEndpointSecuritySensor.app"
    for value in (root, installer, verifier, bundle):
        encoded = os.fsencode(value)
        if len(encoded) > MAX_INSTALL_PATH_BYTES or any(byte < 32 for byte in encoded):
            raise DevelopmentSensorLaunchError("The repair path contains unsupported control characters or exceeds the safe length limit.")
    if not installer.is_file() or not verifier.is_file() or not bundle.is_dir():
        raise DevelopmentSensorLaunchError(
            "The verified Endpoint Security sensor repair bundle is unavailable in this source build."
        )
    return f"cd -- {shlex.quote(str(root))} && sudo -- /bin/sh {shlex.quote(str(installer))}"


def _open_reviewed_command_in_terminal(
    command: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    audit_path: Path | None,
    event_type: str,
) -> TerminalInstallLaunch:
    script = (
        'tell application "Terminal"\n'
        f'  do script "{_apple_script_string(command)}"\n'
        "  activate\n"
        "end tell"
    )
    event_id = str(uuid.uuid4())
    try:
        completed = runner(
            [str(TERMINAL_EXECUTABLE), "-e", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _write_launch_event(event_id, outcome="launch_failed", audit_path=audit_path, event_type=event_type)
        raise DevelopmentSensorLaunchError("Terminal could not be opened. Copy the reviewed command and run it manually.") from exc
    if completed.returncode != 0:
        _write_launch_event(event_id, outcome="launch_failed", audit_path=audit_path, event_type=event_type)
        raise DevelopmentSensorLaunchError("Terminal declined the installation request. Copy the reviewed command and run it manually.")
    _write_launch_event(event_id, outcome="terminal_opened", audit_path=audit_path, event_type=event_type)
    return TerminalInstallLaunch(
        True,
        command,
        event_id,
        "Terminal opened. Review the command, then enter the administrator password only in the macOS sudo prompt.",
    )


def open_development_sensor_install_in_terminal(
    repository_root: Path | None = None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    audit_path: Path | None = None,
) -> TerminalInstallLaunch:
    """Open a new Terminal window containing the reviewed observer install command."""
    return _open_reviewed_command_in_terminal(
        repository_install_command(repository_root),
        runner=runner,
        audit_path=audit_path,
        event_type="RANSOMWARE_DEVELOPMENT_SENSOR_INSTALL_LAUNCH",
    )


def open_development_sensor_repair_in_terminal(
    repository_root: Path | None = None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    audit_path: Path | None = None,
) -> TerminalInstallLaunch:
    """Open Terminal with the fixed runtime-alignment and service repair."""
    return _open_reviewed_command_in_terminal(
        repository_repair_command(repository_root),
        runner=runner,
        audit_path=audit_path,
        event_type="RANSOMWARE_DEVELOPMENT_SENSOR_REPAIR_LAUNCH",
    )


def open_endpoint_security_sensor_repair_in_terminal(
    repository_root: Path | None = None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    audit_path: Path | None = None,
) -> TerminalInstallLaunch:
    """Open Terminal with the fixed signature-gated Endpoint Security repair."""
    return _open_reviewed_command_in_terminal(
        endpoint_security_sensor_repair_command(repository_root),
        runner=runner,
        audit_path=audit_path,
        event_type="RANSOMWARE_ENDPOINT_SECURITY_SENSOR_REPAIR_LAUNCH",
    )


__all__: Sequence[str] = (
    "DevelopmentSensorLaunchError",
    "TerminalInstallLaunch",
    "endpoint_security_sensor_repair_command",
    "open_development_sensor_install_in_terminal",
    "open_development_sensor_repair_in_terminal",
    "open_endpoint_security_sensor_repair_in_terminal",
    "repository_install_command",
    "repository_repair_command",
)
