from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable

ALLOWED = {"/usr/sbin/systemsetup", "/usr/bin/defaults", "/bin/launchctl", "/sbin/pfctl", "/usr/libexec/ApplicationFirewall/socketfilterfw"}


@dataclass(frozen=True)
class EnforcementResult:
    control_id: str
    command: tuple[str, ...]
    success: bool
    returncode: int
    stdout: str
    stderr: str
    changed: bool
    def to_dict(self) -> dict[str, Any]: return asdict(self)


class LockdownEnforcer:
    def __init__(self, runner: Callable[..., Any] | None = None) -> None: self.runner = runner or subprocess.run

    def apply(self, control: dict[str, Any], *, dry_run: bool = False) -> EnforcementResult:
        command = tuple(str(item) for item in control.get("apply", []))
        control_id = str(control.get("id", ""))
        if not command or command[0] not in ALLOWED:
            raise ValueError(f"LOCKDOWN_UNSAFE_CONTROL: {control_id}")
        if dry_run: return EnforcementResult(control_id, command, True, 0, "preview only", "", False)
        completed = self.runner(list(command), capture_output=True, text=True, timeout=20, check=False)
        return EnforcementResult(control_id, command, completed.returncode == 0, int(completed.returncode), (completed.stdout or "")[-8192:], (completed.stderr or "")[-8192:], completed.returncode == 0)

    def rollback(self, control: dict[str, Any], *, dry_run: bool = False) -> EnforcementResult:
        restored = dict(control); restored["apply"] = list(control.get("rollback", [])); restored["id"] = f"rollback:{control.get('id', '')}"
        return self.apply(restored, dry_run=dry_run)
