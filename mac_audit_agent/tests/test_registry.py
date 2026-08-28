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


def test_registry_adds_tactic_oriented_apt_context_without_claiming_attribution() -> None:
    from mac_audit_agent.scan_category_standards import mapping_for, render_mapping

    registry = build_command_registry()
    expected = {
        "attack.execution.interpreter_inventory",
        "attack.persistence.background_items",
        "attack.credential.keychain_locations",
        "attack.defense_evasion.quarantine_metadata",
        "attack.c2.proxy_state",
        "attack.lateral.remote_login_state",
        "attack.impact.snapshot_inventory",
        "attack.supply_chain.package_receipts",
        "attack.collection.external_storage",
    }
    assert expected.issubset(registry)
    for command_id in expected:
        command = registry[command_id]
        mapping = mapping_for(command_id)
        assert command.mutates_system is False
        assert mapping is not None
        assert mapping.nist and mapping.cmmc and mapping.mitre_attack and mapping.cisa
        assert "not proof" in render_mapping(command_id)


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


def test_registry_includes_cmmc_nist_cisa_and_attack_supporting_scans() -> None:
    from mac_audit_agent.scan_category_standards import mapping_for

    registry = build_command_registry()
    expected = {
        "assurance.audit_configuration",
        "assurance.password_policy",
        "assurance.remote_services",
        "assurance.backup_destinations",
        "assurance.network_time",
        "assurance.boot_arguments",
        "assurance.firewall_applications",
        "assurance.install_history",
    }
    assert expected.issubset(registry)
    for command_id in expected:
        mapping = mapping_for(command_id)
        assert mapping is not None
        assert mapping.nist and mapping.cmmc and mapping.mitre_attack and mapping.cisa
        assert registry[command_id].mutates_system is False


def test_standards_mapping_uses_evidence_only_qualification() -> None:
    from mac_audit_agent.scan_category_standards import render_mapping

    rendered = render_mapping("assurance.audit_configuration")
    assert "supporting evidence only" in rendered
    assert "not certification" in rendered
    assert "not proof" in rendered


def test_registry_includes_bounded_attack_discovery_exposure_checks() -> None:
    from mac_audit_agent.scan_category_standards import mapping_for

    registry = build_command_registry()
    expected = {
        "discovery.system_identity",
        "discovery.host_identity",
        "discovery.logged_on_users",
        "discovery.current_account",
        "discovery.mounted_shares",
        "discovery.security_products",
        "discovery.cloud_tooling_locations",
    }
    assert expected.issubset(registry)
    for command_id in expected:
        command = registry[command_id]
        assert command.category == "ATT&CK Discovery Exposure"
        assert command.mutates_system is False
        assert mapping_for(command_id) is not None
