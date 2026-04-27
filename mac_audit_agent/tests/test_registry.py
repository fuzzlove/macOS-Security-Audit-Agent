from mac_audit_agent.command_registry import build_command_registry


def test_registry_contains_only_non_mutating_commands() -> None:
    registry = build_command_registry()
    assert registry
    for command in registry.values():
        assert command.mutates_system is False
        assert command.risk_level in {"safe", "sensitive", "dangerous"}
        assert command.timeout_seconds > 0
        assert command.user_disclaimer
        assert command.safer_alternative
        assert command.risk_level != "dangerous"


def test_registry_has_required_metadata() -> None:
    registry = build_command_registry()
    required_fields = {
        "id",
        "name",
        "description",
        "command",
        "privilege_required",
        "risk_level",
        "mutates_system",
        "timeout_seconds",
        "collection_warning",
        "failure_modes",
        "user_disclaimer",
        "safer_alternative",
    }
    for command in registry.values():
        assert required_fields.issubset(command.to_dict().keys())
