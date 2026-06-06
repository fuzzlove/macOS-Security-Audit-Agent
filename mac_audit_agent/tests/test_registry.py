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


def test_registry_exposes_expanded_detection_coverage() -> None:
    registry = build_command_registry()
    categories = {command.category for command in registry.values()}
    expected_categories = {
        "Accounts & Privileges",
        "Browser Security",
        "Extensions & Drivers",
        "Files & Processes",
        "macOS Security",
        "Network",
        "Persistence",
        "Policy & Management",
        "Privacy Permissions",
    }
    expected_commands = {
        "accounts.ssh_authorized_keys_locations",
        "extensions.system_extensions",
        "files.writable_exec_locations",
        "network.routing_table",
        "persistence.native_messaging_hosts",
        "security.configuration_profiles",
        "security.tcc_user_database",
        "security.xprotect_version",
    }

    assert len(registry) >= 50
    assert expected_categories.issubset(categories)
    assert expected_commands.issubset(registry)


def test_registry_scan_commands_are_bounded_read_only_artifact_checks() -> None:
    registry = build_command_registry()
    prohibited_executables = {"rm", "mv", "cp", "chmod", "chown", "kill", "pkill"}
    prohibited_phrases = {"launchctl unload", "defaults write"}

    for command in registry.values():
        preview = " ".join(command.command)
        assert command.mutates_system is False
        assert command.command[0].split("/")[-1] not in prohibited_executables
        assert not any(phrase in preview for phrase in prohibited_phrases)
        assert command.timeout_seconds <= 20
