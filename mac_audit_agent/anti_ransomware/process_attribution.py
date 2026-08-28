"""Best-effort local process attribution without credential or content capture."""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProcessAttribution:
    pid: int
    parent_pid: int | None
    process_path: str
    team_id: str = ""
    signing_state: str = "not_inspected"
    limitation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def attribute_process(pid: int) -> ProcessAttribution:
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "ppid=", "-o", "comm="], capture_output=True,
                                text=True, timeout=2, check=False)
        fields = result.stdout.strip().split(None, 1)
        return ProcessAttribution(pid, int(fields[0]) if fields else None, fields[1] if len(fields) > 1 else "",
                                  limitation="Code-signing metadata requires an installed macOS sensor." if os.name != "posix" else "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return ProcessAttribution(pid, None, "", limitation=f"Process metadata unavailable: {type(exc).__name__}")


__all__ = ["ProcessAttribution", "attribute_process"]
