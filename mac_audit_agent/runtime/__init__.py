from __future__ import annotations

__all__ = [
    "CommandExecutionResult",
    "CommandOrigin",
    "CommandSafetyLevel",
    "InternalCommandExecutor",
    "execute_internal_command",
]


def __getattr__(name: str):
    if name in {"CommandExecutionResult", "CommandOrigin", "CommandSafetyLevel"}:
        from mac_audit_agent.runtime import command_models

        return getattr(command_models, name)
    if name in {"InternalCommandExecutor", "execute_internal_command"}:
        from mac_audit_agent.runtime import internal_command_executor

        return getattr(internal_command_executor, name)
    raise AttributeError(name)
