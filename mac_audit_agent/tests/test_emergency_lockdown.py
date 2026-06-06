from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.emergency_lockdown import (
    ACTION_LOG_STATE_KEY,
    CONFIRMATION_TEXT,
    FAILURE_ACTIVATION_UNKNOWN,
    FAILURE_DRY_RUN,
    FAILURE_SYSTEM_REJECTED_REQUEST,
    FAILURE_UNSUPPORTED_AUTOMATIC_ACTIVATION,
    LAST_ACTION_STATE_KEY,
    POLICY_DISABLED,
    POLICY_ATTEMPT_ACTIVATION,
    POLICY_RECOMMEND_ONLY,
    TRACE_LOG_STATE_KEY,
    enable_lockdown_with_user_policy,
    get_lockdown_status,
    lockdown_mode_capability,
    load_policy,
    save_policy,
)
from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.storage import AuditDatabase


def _db(tmp_path: Path) -> AuditDatabase:
    return AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")


def _event(*, severity: str = "critical", confidence: str = "high", event_type: str = "protected_monitor_tamper_detected") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id="event-1",
        timestamp="2026-06-01T00:00:00+00:00",
        event_type=event_type,
        severity=severity,
        source="test",
        evidence="test",
        confidence=confidence,
    )


def _runner(commands: list[list[str]]):
    def run(command, **_kwargs):
        commands.append(list(command))
        if command[:2] == ["/usr/bin/defaults", "read"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
        if command[:1] == ["/usr/bin/open"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported")

    return run


def test_default_policy_disabled(tmp_path: Path) -> None:
    db = _db(tmp_path)

    assert load_policy(db)["mode"] == POLICY_RECOMMEND_ONLY


def test_opt_in_and_typed_confirmation_required(tmp_path: Path) -> None:
    db = _db(tmp_path)

    with pytest.raises(ValueError):
        save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=False, confirmation="")
    with pytest.raises(ValueError):
        save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation="ENABLE")

    policy = save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    assert policy["mode"] == POLICY_ATTEMPT_ACTIVATION


def test_low_confidence_event_does_not_trigger_or_audit(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)

    action = enable_lockdown_with_user_policy(db, _event(confidence="medium"), runner=_runner([]))

    assert action.action_attempted == "none"
    assert db.get_background_monitor_state(ACTION_LOG_STATE_KEY, "") == ""


def test_critical_event_creates_snapshot_before_action(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    commands: list[list[str]] = []
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=_runner(commands))

    assert action.snapshot_created is True
    assert action.action_attempted == "assist_user"
    assert action.action_success is False
    assert action.requires_user_action is True
    assert action.settings_opened is True
    assert action.snapshot_path
    assert any(command[:1] == ["/usr/bin/open"] for command in commands)
    assert db.list_system_recovery_snapshots(limit=1)


def test_critical_event_attempts_lockdown_only_when_enabled(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_DISABLED, understood=False, confirmation="")
    commands: list[list[str]] = []

    action = enable_lockdown_with_user_policy(db, _event(), runner=_runner(commands))

    assert action.policy_mode == POLICY_DISABLED
    assert action.action_attempted == "none"
    assert not any(command[:1] == ["/usr/bin/open"] for command in commands)


def test_unsupported_macos_opens_fallback_guidance(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    commands: list[list[str]] = []
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=_runner(commands))

    assert action.action_attempted == "assist_user"
    assert action.action_success is False
    assert FAILURE_UNSUPPORTED_AUTOMATIC_ACTIVATION in action.error
    assert action.activation_method == "assist_user_settings_deep_link"
    assert action.activation_supported is False
    assert action.assisted_activation_supported is True
    assert action.requires_user_action is True
    assert any(command[:1] == ["/usr/bin/open"] for command in commands)


def test_action_is_audited(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=_runner([]))
    last = json.loads(db.get_background_monitor_state(LAST_ACTION_STATE_KEY, "{}"))

    assert last["trigger_event_id"] == action.trigger_event_id
    assert last["action_attempted"] == "assist_user"


def test_lockdown_trace_records_command_and_verification_failure(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=_runner([]))
    traces = json.loads(db.get_background_monitor_state(TRACE_LOG_STATE_KEY, "[]"))

    assert action.action_success is False
    assert traces
    assert traces[-1]["trigger_event"] == "protected_monitor_tamper_detected"
    assert traces[-1]["trigger_event_id"] == "event-1"
    assert traces[-1]["confidence"] == "high"
    assert traces[-1]["dry_run"] is False
    assert traces[-1]["action_attempted"] == "assist_user"
    assert traces[-1]["activation_supported"] is False
    assert traces[-1]["automatic_activation_supported"] is False
    assert traces[-1]["assisted_activation_supported"] is True
    assert traces[-1]["requires_user_action"] is True
    assert traces[-1]["settings_opened"] is True
    assert traces[-1]["activation_method"] == "assist_user_settings_deep_link"
    assert traces[-1]["command"] == "/usr/bin/open"
    assert traces[-1]["arguments"]
    assert traces[-1]["return_code"] == 0
    assert traces[-1]["lockdown_status_after"] == "unknown"
    assert traces[-1]["status_confidence"] == "low"
    assert traces[-1]["verification_method"] == "defaults_preference_probes"
    assert traces[-1]["verification_result"]
    assert traces[-1]["success"] is False
    assert FAILURE_UNSUPPORTED_AUTOMATIC_ACTIVATION in traces[-1]["failure_reason"]


def test_lockdown_trace_classifies_settings_open_failure(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    def runner(command, **_kwargs):
        if command[:2] == ["/usr/bin/defaults", "read"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
        if command[:1] == ["/usr/bin/open"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="No application knows this URL")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=runner)
    traces = json.loads(db.get_background_monitor_state(TRACE_LOG_STATE_KEY, "[]"))

    assert action.action_success is False
    assert FAILURE_SYSTEM_REJECTED_REQUEST in action.error
    assert FAILURE_SYSTEM_REJECTED_REQUEST in traces[-1]["failure_reason"]


def test_dry_run_does_not_change_system(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    commands: list[list[str]] = []

    action = enable_lockdown_with_user_policy(db, _event(), runner=_runner(commands), dry_run=True)

    assert action.dry_run is True
    assert action.action_attempted == "dry_run"
    assert action.policy_mode == "dry_run_only"
    assert action.configured_policy_mode == POLICY_ATTEMPT_ACTIVATION
    assert action.action_success is False
    assert FAILURE_DRY_RUN in action.error
    traces = json.loads(db.get_background_monitor_state(TRACE_LOG_STATE_KEY, "[]"))
    assert traces[-1]["dry_run"] is True
    assert traces[-1]["policy_mode"] == "dry_run_only"
    assert traces[-1]["configured_policy_mode"] == POLICY_ATTEMPT_ACTIVATION
    assert traces[-1]["activation_method"] == "dry_run"
    assert "No Lockdown Mode change was attempted" in traces[-1]["failure_reason"]
    assert not any(command[:1] == ["/usr/bin/open"] for command in commands)


def test_attempt_activation_does_not_execute_dry_run_when_unsupported(tmp_path: Path) -> None:
    db = _db(tmp_path)
    save_policy(db, mode=POLICY_ATTEMPT_ACTIVATION, understood=True, confirmation=CONFIRMATION_TEXT)
    commands: list[list[str]] = []
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache", recovery_snapshot_dir=tmp_path / "snapshots")

    action = enable_lockdown_with_user_policy(db, _event(), config=config, runner=_runner(commands), dry_run=False)

    assert action.policy_mode == POLICY_ATTEMPT_ACTIVATION
    assert action.dry_run is False
    assert action.action_attempted == "assist_user"
    assert action.activation_method == "assist_user_settings_deep_link"
    assert FAILURE_DRY_RUN not in action.error


def test_missing_defaults_key_results_in_unknown_low_confidence_status() -> None:
    commands: list[list[str]] = []
    status = get_lockdown_status(_runner(commands))

    assert status["status"] == "unknown"
    assert status["confidence"] == "low"
    assert status["public_status_api"] is False


def test_explicit_disabled_defaults_value_is_low_confidence_disabled() -> None:
    def runner(command, **_kwargs):
        if command[:2] == ["/usr/bin/defaults", "read"]:
            return subprocess.CompletedProcess(command, 0, stdout="0\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

    status = get_lockdown_status(runner)

    assert status["status"] == "disabled"
    assert status["confidence"] == "low"


def test_capability_marks_settings_deep_link_as_assisted_only() -> None:
    capability = lockdown_mode_capability(_runner([]))

    if capability.lockdown_available:
        assert capability.automatic_activation_supported is False
        assert capability.assisted_activation_supported is True
        assert "user confirmation/restart" in capability.reason
