from __future__ import annotations

import hashlib
import inspect
import json
import logging
import subprocess
import time
import traceback
from pathlib import Path
from typing import Any, Sequence
from uuid import uuid4

from mac_audit_agent.events.command_event_normalizer import CommandEventNormalizer
from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.runtime.command_models import CommandExecutionResult, CommandOrigin, CommandSafetyLevel

LOGGER = logging.getLogger(__name__)


class InternalCommandExecutor:
    def __init__(self, db: Any | None = None, *, audit_log_path: Path | None = None) -> None:
        self.db = db
        self.audit_log_path = audit_log_path
        self.normalizer = CommandEventNormalizer()

    def execute(
        self,
        command: Sequence[str],
        *,
        origin: CommandOrigin,
        safety_level: CommandSafetyLevel = CommandSafetyLevel.SAFE,
        cwd: str | Path | None = None,
        timeout: float | None = 30,
        caller_module: str | None = None,
        execution_context: dict[str, Any] | None = None,
        allow_restricted: bool = False,
    ) -> CommandExecutionResult:
        if not command:
            raise ValueError("command must contain at least one argument")
        if not isinstance(origin, CommandOrigin):
            origin = CommandOrigin(str(origin))
        if not isinstance(safety_level, CommandSafetyLevel):
            safety_level = CommandSafetyLevel(str(safety_level))
        if safety_level == CommandSafetyLevel.RESTRICTED and not allow_restricted:
            raise PermissionError("restricted internal commands require explicit confirmation")

        started = time.monotonic()
        timestamp = utc_now_iso()
        args = [str(item) for item in command]
        command_string = " ".join(args)
        command_id = f"cmd-{uuid4()}"
        stack_ref = self._stack_trace_reference()
        module = caller_module or self._caller_module()
        command_hash = hashlib.sha256("\0".join(args).encode("utf-8")).hexdigest()
        context = dict(execution_context or {})
        context.setdefault("origin", origin.value)
        context.setdefault("safety_level", safety_level.value)

        stdout = ""
        stderr = ""
        exit_code: int | None = None
        status = "completed"
        try:
            completed = subprocess.run(
                args,
                cwd=str(cwd) if cwd is not None else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode
            if completed.returncode != 0:
                status = "failed"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            exit_code = None
            status = "timed_out"
        except OSError as exc:
            stderr = str(exc)
            exit_code = None
            status = "error"

        duration_ms = int((time.monotonic() - started) * 1000)
        result = CommandExecutionResult(
            command_id=command_id,
            command_string=command_string,
            args=args,
            cwd=str(cwd or ""),
            timestamp=timestamp,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            execution_status=status,
            origin=origin,
            safety_level=safety_level,
            command_hash=command_hash,
            caller_module=module,
            stack_trace_ref=stack_ref,
            execution_context=context,
        )
        self._record_result(result)
        return result

    def _record_result(self, result: CommandExecutionResult) -> None:
        if self.db is not None and hasattr(self.db, "record_internal_command_execution"):
            self.db.record_internal_command_execution(result)
            event = self.normalizer.normalize(result)
            if hasattr(self.db, "record_background_monitor_event"):
                self.db.record_background_monitor_event(event, dedupe_window_seconds=0)
            if hasattr(self.db, "record_event_alert_trace"):
                self.db.record_event_alert_trace(self.normalizer.trace_for(result, event, db_path=str(getattr(self.db, "path", ""))))
        if self.audit_log_path is not None:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")
        LOGGER.info(
            "internal command execution recorded command_id=%s origin=%s status=%s hash=%s",
            result.command_id,
            result.origin.value,
            result.execution_status,
            result.command_hash,
        )

    def _caller_module(self) -> str:
        for frame in inspect.stack()[2:]:
            module = inspect.getmodule(frame.frame)
            name = getattr(module, "__name__", "")
            if name and name != __name__:
                return name
        return __name__

    def _stack_trace_reference(self) -> str:
        digest = hashlib.sha256("".join(traceback.format_stack(limit=8)).encode("utf-8")).hexdigest()
        return f"stack-sha256:{digest}"


def execute_internal_command(
    command: Sequence[str],
    origin: CommandOrigin,
    safety_level: CommandSafetyLevel = CommandSafetyLevel.SAFE,
    **kwargs: Any,
) -> CommandExecutionResult:
    return InternalCommandExecutor(db=kwargs.pop("db", None), audit_log_path=kwargs.pop("audit_log_path", None)).execute(
        command,
        origin=origin,
        safety_level=safety_level,
        **kwargs,
    )
