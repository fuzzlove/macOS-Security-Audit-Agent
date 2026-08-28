from pathlib import Path

import pytest

from mac_audit_agent.anti_ransomware.terminal_install import (
    DevelopmentSensorLaunchError,
    endpoint_security_sensor_repair_command,
    open_development_sensor_install_in_terminal,
    open_development_sensor_repair_in_terminal,
    open_endpoint_security_sensor_repair_in_terminal,
    repository_install_command,
    repository_repair_command,
)


def _source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "MSAA project"
    (root / ".venv/bin").mkdir(parents=True)
    (root / ".venv/bin/python").write_text("", encoding="utf-8")
    (root / "launcher.py").write_text("", encoding="utf-8")
    return root


def test_copyable_command_is_absolute_quoted_and_fixed(tmp_path):
    root = _source_tree(tmp_path)
    command = repository_install_command(root)
    assert "sudo --" in command
    assert "'" in command  # space-bearing source root is shell quoted
    assert "--install-protection-services" in command
    assert "--allow-unsigned-development-runtime" in command


def test_terminal_launch_uses_osascript_without_a_shell_or_password(tmp_path):
    root = _source_tree(tmp_path)
    calls = []

    class Result:
        returncode = 0

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return Result()

    audit = tmp_path / "audit/events.jsonl"
    result = open_development_sensor_install_in_terminal(root, runner=runner, audit_path=audit)
    arguments, options = calls[0]
    assert arguments[0] == "/usr/bin/osascript"
    assert arguments[1] == "-e"
    assert options["stdin"] is not None
    assert "shell" not in options
    assert "password" not in arguments[2].lower()
    assert result.launched is True
    text = audit.read_text(encoding="utf-8")
    assert "terminal_opened" in text
    assert result.command not in text


def test_copyable_repair_command_refreshes_protection_services(tmp_path):
    root = _source_tree(tmp_path)
    command = repository_repair_command(root)
    assert "sudo --" in command
    assert "--repair-protection-services" in command
    assert "--developer-mode" in command
    assert "--allow-unsigned-development-runtime" in command
    assert "--install-protection-services" not in command


def test_terminal_repair_launch_is_audited_without_recording_command(tmp_path):
    root = _source_tree(tmp_path)
    calls = []

    class Result:
        returncode = 0

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return Result()

    audit = tmp_path / "audit/events.jsonl"
    result = open_development_sensor_repair_in_terminal(root, runner=runner, audit_path=audit)
    assert calls[0][0][0] == "/usr/bin/osascript"
    assert "--repair-protection-services" in calls[0][0][2]
    text = audit.read_text(encoding="utf-8")
    assert "RANSOMWARE_DEVELOPMENT_SENSOR_REPAIR_LAUNCH" in text
    assert result.command not in text


def test_missing_source_installer_fails_safely(tmp_path):
    with pytest.raises(DevelopmentSensorLaunchError, match="unavailable"):
        repository_install_command(tmp_path)


def _endpoint_sensor_source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "MSAA endpoint project"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts/install_development_endpoint_security_sensor.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "scripts/verify_endpoint_security_signature.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "dist/active-containment/MSAAEndpointSecuritySensor.app").mkdir(parents=True)
    return root


def test_endpoint_security_repair_command_is_fixed_and_signature_gated(tmp_path):
    root = _endpoint_sensor_source_tree(tmp_path)
    command = endpoint_security_sensor_repair_command(root)
    assert command.startswith("cd -- ")
    assert "sudo -- /bin/sh" in command
    assert "install_development_endpoint_security_sensor.sh" in command
    assert "MSAAEndpointSecuritySensor.app" not in command


def test_endpoint_security_repair_opens_terminal_without_password(tmp_path):
    root = _endpoint_sensor_source_tree(tmp_path)
    calls = []

    class Result:
        returncode = 0

    def runner(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return Result()

    audit = tmp_path / "audit/events.jsonl"
    result = open_endpoint_security_sensor_repair_in_terminal(root, runner=runner, audit_path=audit)
    arguments, options = calls[0]
    assert arguments[0] == "/usr/bin/osascript"
    assert "install_development_endpoint_security_sensor.sh" in arguments[2]
    assert "password" not in arguments[2].lower()
    assert options["stdin"] is not None
    assert result.launched is True
    assert "RANSOMWARE_ENDPOINT_SECURITY_SENSOR_REPAIR_LAUNCH" in audit.read_text(encoding="utf-8")
