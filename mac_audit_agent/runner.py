from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from datetime import timezone, datetime
from pathlib import Path

from mac_audit_agent.models import AuditCommand, CommandExecutionResult


@dataclass(frozen=True)
class RunnerConfig:
    dry_run: bool = False
    max_output_bytes: int = 32_768


class SafeCommandRunner:
    def __init__(self, config: RunnerConfig | None = None) -> None:
        self.config = config or RunnerConfig()

    def preview_command(self, command: AuditCommand) -> str:
        return shlex.join(command.command)

    def execute(self, command: AuditCommand, approval_token: str | None = None) -> CommandExecutionResult:
        executed_at = datetime.now(timezone.utc).isoformat()
        preview = self.preview_command(command)
        if command.risk_level == "dangerous" and approval_token != "RUN":
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=preview,
                executed_at=executed_at,
                stdout="",
                stderr="Dangerous command blocked pending explicit approval token.",
                exit_code=126,
                timed_out=False,
                truncated=False,
                dry_run=self.config.dry_run,
            )
        resolved_command = [str(Path(part).expanduser()) if part.startswith("~") else part for part in command.command]
        if self.config.dry_run:
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=preview,
                executed_at=executed_at,
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                truncated=False,
                dry_run=True,
            )

        try:
            completed = subprocess.run(
                resolved_command,
                capture_output=True,
                text=True,
                timeout=command.timeout_seconds,
                check=False,
            )
            stdout, stderr, truncated = self._trim_output(completed.stdout, completed.stderr)
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=preview,
                executed_at=executed_at,
                stdout=stdout,
                stderr=stderr,
                exit_code=completed.returncode,
                timed_out=False,
                truncated=truncated,
                dry_run=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, truncated = self._trim_output(exc.stdout or "", exc.stderr or "Command timed out.")
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=preview,
                executed_at=executed_at,
                stdout=stdout,
                stderr=stderr,
                exit_code=124,
                timed_out=True,
                truncated=truncated,
                dry_run=False,
            )
        except OSError as exc:
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=preview,
                executed_at=executed_at,
                stdout="",
                stderr=str(exc),
                exit_code=1,
                timed_out=False,
                truncated=False,
                dry_run=False,
            )

    def _trim_output(self, stdout: str, stderr: str) -> tuple[str, str, bool]:
        raw = (stdout + stderr).encode("utf-8", errors="replace")
        if len(raw) <= self.config.max_output_bytes:
            return stdout, stderr, False

        remaining = self.config.max_output_bytes
        stdout_bytes = stdout.encode("utf-8", errors="replace")
        stderr_bytes = stderr.encode("utf-8", errors="replace")

        trimmed_stdout = stdout_bytes[:remaining]
        remaining -= len(trimmed_stdout)
        trimmed_stderr = stderr_bytes[:max(remaining, 0)]

        return (
            trimmed_stdout.decode("utf-8", errors="replace"),
            trimmed_stderr.decode("utf-8", errors="replace") + "\n[truncated]",
            True,
        )
