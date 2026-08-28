from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.performance.memory import cap_text_output
from mac_audit_agent.performance.resource_budget import load_resource_budget


@dataclass
class BoundedCommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    completed_at: str
    timed_out: bool = False
    output_truncated: bool = False
    error: str = ""
    diagnostic_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_bounded_command(
    args: list[str],
    timeout_seconds: int | None = None,
    max_output_bytes: int = 1_000_000,
    priority: str = "background_normal",
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> BoundedCommandResult:
    budget = load_resource_budget()
    timeout = timeout_seconds or budget.scan_timeout_seconds
    safe_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    if env:
        safe_env.update({str(key): str(value) for key, value in env.items()})
    started = utc_now_iso()
    try:
        completed = subprocess.run(
            [str(item) for item in args],
            capture_output=True,
            text=False,
            check=False,
            timeout=timeout,
            env=safe_env,
            cwd=cwd,
        )
        raw_stdout = completed.stdout or b""
        raw_stderr = completed.stderr or b""
        stdout = cap_text_output(raw_stdout, max_output_bytes)
        stderr = cap_text_output(raw_stderr, max_output_bytes)
        return BoundedCommandResult(
            args=[str(item) for item in args],
            returncode=int(completed.returncode),
            stdout=stdout,
            stderr=stderr,
            started_at=started,
            completed_at=utc_now_iso(),
            output_truncated=len(raw_stdout) > max_output_bytes or len(raw_stderr) > max_output_bytes,
            diagnostic_details={"priority": priority, "pid": os.getpid(), "timeout_seconds": timeout},
        )
    except subprocess.TimeoutExpired as exc:
        return BoundedCommandResult(
            args=[str(item) for item in args],
            returncode=124,
            stdout=cap_text_output(exc.stdout or b"", max_output_bytes),
            stderr=cap_text_output(exc.stderr or b"", max_output_bytes),
            started_at=started,
            completed_at=utc_now_iso(),
            timed_out=True,
            error=f"Command timed out after {timeout} seconds.",
            diagnostic_details={"priority": priority, "timeout_seconds": timeout},
        )
    except OSError as exc:
        return BoundedCommandResult(
            args=[str(item) for item in args],
            returncode=1,
            stdout="",
            stderr=str(exc),
            started_at=started,
            completed_at=utc_now_iso(),
            error=str(exc),
            diagnostic_details={"priority": priority, "timeout_seconds": timeout},
        )
