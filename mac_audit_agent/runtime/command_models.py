from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class CommandOrigin(StrEnum):
    USER_INITIATED = "USER_INITIATED"
    SYSTEM_MONITOR = "SYSTEM_MONITOR"
    INTERNAL_MSAA_TASK = "INTERNAL_MSAA_TASK"
    DIAGNOSTIC = "DIAGNOSTIC"
    REPAIR_WIZARD = "REPAIR_WIZARD"
    ALERT_PIPELINE = "ALERT_PIPELINE"
    TEST_FRAMEWORK = "TEST_FRAMEWORK"


class CommandSafetyLevel(StrEnum):
    SAFE = "SAFE"
    CONTROLLED = "CONTROLLED"
    RESTRICTED = "RESTRICTED"


@dataclass(frozen=True)
class CommandExecutionResult:
    command_id: str
    command_string: str
    args: list[str]
    cwd: str
    timestamp: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    execution_status: str
    origin: CommandOrigin
    safety_level: CommandSafetyLevel
    command_hash: str
    caller_module: str
    stack_trace_ref: str
    execution_context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["origin"] = self.origin.value
        payload["safety_level"] = self.safety_level.value
        return payload
