from mac_audit_agent.anti_ransomware.install_guidance import DEVELOPMENT_INSTALL_COMMAND, development_sensor_install_guide


def test_development_sensor_is_hosted_in_existing_system_monitor():
    guide = development_sensor_install_guide({"system_daemon": {"installed": True, "running": True}})
    assert guide["architecture"] == "hosted_in_existing_system_monitor_launchdaemon"
    assert guide["launchd_label"] == "com.mac-audit-agent.monitor"
    assert guide["running"] is True
    assert guide["installation_required"] is False


def test_install_guide_is_explicit_about_privilege_and_endpoint_security_limits():
    guide = development_sensor_install_guide()
    assert guide["administrator_approval_required"] is True
    assert guide["gui_runs_as_root"] is False
    assert guide["password_collected_by_msaa"] is False
    assert "sudo " in DEVELOPMENT_INSTALL_COMMAND
    assert "--allow-unsigned-development-runtime" in DEVELOPMENT_INSTALL_COMMAND
    assert any("Endpoint Security" in item for item in guide["not_provided_without_apple_entitlement"])
    assert guide["expected_production_state"].startswith("DEGRADED_OBSERVATION_ONLY")
