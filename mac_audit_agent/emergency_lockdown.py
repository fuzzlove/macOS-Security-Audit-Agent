from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable, Protocol

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.recovery_center import SystemRecoveryCenter


POLICY_DISABLED = "disabled"
POLICY_RECOMMEND_ONLY = "recommend_only"
POLICY_ASSIST_USER = "assist_user"
POLICY_ATTEMPT_ACTIVATION = "attempt_activation"
POLICY_MANAGED_ENVIRONMENT = "managed_environment"
POLICY_ASK = "ask"
POLICY_AUTO = "auto"
POLICY_AUTO_AFTER_SNAPSHOT = "auto_after_snapshot"
POLICY_DRY_RUN_ONLY = "dry_run_only"
CONFIRMATION_TEXT = "ENABLE LOCKDOWN AUTO RESPONSE"
POLICY_STATE_KEY = "emergency_lockdown_policy_json"
ACTION_LOG_STATE_KEY = "emergency_lockdown_actions_json"
TRACE_LOG_STATE_KEY = "emergency_lockdown_traces_json"
LAST_ACTION_STATE_KEY = "emergency_lockdown_last_action_json"
LAST_TRACE_STATE_KEY = "emergency_lockdown_last_trace_json"
LAST_FAILURE_STATE_KEY = "emergency_lockdown_last_failure"
LOCKDOWN_SETTINGS_URL = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?LockdownMode"
FAILURE_UNSUPPORTED_OS = "unsupported_os"
FAILURE_UNSUPPORTED_API = "unsupported_api"
FAILURE_MISSING_PERMISSION = "missing_permission"
FAILURE_USER_APPROVAL_REQUIRED = "user_approval_required"
FAILURE_VERIFICATION_FAILED = "verification_failed"
FAILURE_ACTIVATION_FAILED = "activation_failed"
FAILURE_ACTIVATION_UNKNOWN = "activation_unknown"
FAILURE_SETTINGS_NOT_FOUND = "settings_not_found"
FAILURE_SYSTEM_REJECTED_REQUEST = "system_rejected_request"
FAILURE_CONFIGURATION_PROFILE_REQUIRED = "configuration_profile_required"
FAILURE_MANAGED_ENVIRONMENT_REQUIRED = "managed_environment_required"
FAILURE_INTERNAL_EXCEPTION = "internal_exception"
FAILURE_UNKNOWN = "unknown"
FAILURE_DRY_RUN = "dry_run"
FAILURE_UNSUPPORTED_AUTOMATIC_ACTIVATION = "unsupported_automatic_activation"


class LockdownResponseMode(str, Enum):
    DISABLED = POLICY_DISABLED
    RECOMMEND_ONLY = POLICY_RECOMMEND_ONLY
    ASSIST_USER = POLICY_ASSIST_USER
    ATTEMPT_ACTIVATION = POLICY_ATTEMPT_ACTIVATION
    MANAGED_ENVIRONMENT = POLICY_MANAGED_ENVIRONMENT


class StateStore(Protocol):
    def get_background_monitor_state(self, key: str, default: str = "") -> str: ...

    def set_background_monitor_state(self, key: str, value: str) -> None: ...


@dataclass(frozen=True)
class EmergencyLockdownAction:
    timestamp: str
    trigger_event_id: str
    trigger_reason: str
    confidence: str
    policy_mode: str
    snapshot_created: bool
    lockdown_status_before: str
    lockdown_status_after: str
    action_attempted: str
    action_success: bool
    configured_policy_mode: str = ""
    error: str = ""
    user_visible_notice_shown: bool = False
    dry_run: bool = False
    activation_method: str = ""
    activation_supported: bool = False
    assisted_activation_supported: bool = False
    requires_user_action: bool = False
    settings_opened: bool = False
    snapshot_path: str = ""
    status_confidence: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LockdownActivationTrace:
    timestamp: str
    trigger_event: str
    trigger_event_id: str
    confidence: str
    policy_mode: str
    configured_policy_mode: str
    dry_run: bool
    action_attempted: str
    snapshot_created: bool
    snapshot_path: str
    lockdown_status_before: str
    activation_supported: bool
    automatic_activation_supported: bool
    assisted_activation_supported: bool
    activation_method: str
    activation_path: str
    requires_user_action: bool
    settings_opened: bool
    command: str
    arguments: list[str]
    return_code: int | None
    stdout: str
    stderr: str
    exception: str
    verification_method: str
    verification_result: str
    lockdown_status_after: str
    status_confidence: str
    success: bool
    failure_reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LockdownModeTrace = LockdownActivationTrace


@dataclass(frozen=True)
class LockdownModeCapability:
    macos_version: str
    lockdown_available: bool
    status_detection_supported: bool
    automatic_activation_supported: bool
    assisted_activation_supported: bool
    managed_activation_supported: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_policy() -> dict[str, Any]:
    return {
        "mode": POLICY_RECOMMEND_ONLY,
        "understood": False,
        "confirmation": "",
        "require_admin_approval": True,
        "create_snapshot_first": True,
        "developer_mode_export_simulated": False,
    }


def load_policy(store: StateStore) -> dict[str, Any]:
    raw = store.get_background_monitor_state(POLICY_STATE_KEY, "")
    if not raw:
        return default_policy()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return default_policy()
    if not isinstance(payload, dict):
        return default_policy()
    policy = default_policy()
    policy.update(payload)
    if policy.get("mode") not in {
        POLICY_DISABLED,
        POLICY_RECOMMEND_ONLY,
        POLICY_ASSIST_USER,
        POLICY_ATTEMPT_ACTIVATION,
        POLICY_MANAGED_ENVIRONMENT,
        POLICY_ASK,
        POLICY_AUTO,
        POLICY_AUTO_AFTER_SNAPSHOT,
    }:
        policy["mode"] = POLICY_RECOMMEND_ONLY
    return policy


def save_policy(
    store: StateStore,
    *,
    mode: str,
    understood: bool,
    confirmation: str,
    require_admin_approval: bool = True,
    create_snapshot_first: bool = True,
    developer_mode_export_simulated: bool = False,
) -> dict[str, Any]:
    legacy_mode_map = {
        POLICY_ASK: POLICY_ASSIST_USER,
        POLICY_AUTO: POLICY_ATTEMPT_ACTIVATION,
        POLICY_AUTO_AFTER_SNAPSHOT: POLICY_ATTEMPT_ACTIVATION,
    }
    mode = legacy_mode_map.get(mode, mode)
    mode = mode if mode in {
        POLICY_DISABLED,
        POLICY_RECOMMEND_ONLY,
        POLICY_ASSIST_USER,
        POLICY_ATTEMPT_ACTIVATION,
        POLICY_MANAGED_ENVIRONMENT,
    } else POLICY_RECOMMEND_ONLY
    if mode == POLICY_ATTEMPT_ACTIVATION and (not understood or confirmation.strip() != CONFIRMATION_TEXT):
        raise ValueError("Automatic Emergency Lockdown requires the warning checkbox and exact typed confirmation.")
    policy = {
        "mode": mode,
        "understood": bool(understood),
        "confirmation": confirmation.strip() if mode == POLICY_ATTEMPT_ACTIVATION else "",
        "require_admin_approval": bool(require_admin_approval),
        "create_snapshot_first": bool(create_snapshot_first),
        "developer_mode_export_simulated": bool(developer_mode_export_simulated),
    }
    store.set_background_monitor_state(POLICY_STATE_KEY, json.dumps(policy, sort_keys=True))
    return policy


def get_lockdown_status(runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    runner = runner or subprocess.run
    observed = "unknown"
    confidence = "low"
    evidence = "No stable public command-line status API is available; known preference probes did not prove state."
    probes: list[dict[str, Any]] = []
    for domain, key in [
        ("com.apple.security", "LockdownMode"),
        ("com.apple.Safari", "LockdownMode"),
        ("com.apple.Safari", "LockdownModeEnabled"),
    ]:
        command = ["/usr/bin/defaults", "read", domain, key]
        try:
            completed = runner(command, capture_output=True, text=True, timeout=3, check=False)
            output = (getattr(completed, "stdout", "") or getattr(completed, "stderr", "") or "").strip()
            return_code = int(getattr(completed, "returncode", 1) or 0)
            probes.append(
                {
                    "command": command,
                    "return_code": return_code,
                    "stdout": (getattr(completed, "stdout", "") or "").strip(),
                    "stderr": (getattr(completed, "stderr", "") or "").strip(),
                }
            )
            normalized_output = output.strip()
            if normalized_output in {"1", "true", "TRUE", "YES", "yes"}:
                observed = "enabled"
                confidence = "medium"
                evidence = f"defaults read {domain} {key}: {output}"
                break
            if normalized_output in {"0", "false", "FALSE", "NO", "no"}:
                observed = "disabled"
                confidence = "low"
                evidence = f"defaults read {domain} {key}: {output}"
                break
        except Exception as exc:
            probes.append({"command": command, "exception": str(exc)})
            continue
    return {
        "status": observed,
        "confidence": confidence,
        "evidence": evidence,
        "platform": platform.platform(),
        "public_status_api": False,
        "probes": probes,
    }


def _macos_major_version(version: str) -> int:
    try:
        return int((version or "").split(".")[0])
    except (ValueError, TypeError):
        return 0


def lockdown_mode_capability(runner: Callable[..., Any] | None = None) -> LockdownModeCapability:
    macos_version = platform.mac_ver()[0] or platform.release()
    lockdown_available = _macos_major_version(macos_version) >= 13
    if not lockdown_available:
        return LockdownModeCapability(
            macos_version=macos_version,
            lockdown_available=False,
            status_detection_supported=False,
            automatic_activation_supported=False,
            assisted_activation_supported=False,
            managed_activation_supported=False,
            reason="Lockdown Mode is available on macOS Ventura 13 or later.",
        )
    status = get_lockdown_status(runner)
    return LockdownModeCapability(
        macos_version=macos_version,
        lockdown_available=True,
        status_detection_supported=str(status.get("status", "unknown")) != "unknown",
        automatic_activation_supported=False,
        assisted_activation_supported=True,
        managed_activation_supported=False,
        reason="macOS requires user confirmation/restart for Lockdown Mode activation.",
    )


def can_enable_lockdown(runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    capability = lockdown_mode_capability(runner)
    return {
        "supported": capability.automatic_activation_supported,
        "method": "automatic_public_api" if capability.automatic_activation_supported else "assist_user_settings_deep_link",
        "path": "" if capability.automatic_activation_supported else LOCKDOWN_SETTINGS_URL,
        "reason": capability.reason,
        "requires_user_interaction": not capability.automatic_activation_supported,
        "requires_admin_or_user_password": True,
        "requires_restart": True,
        "permission_level": "interactive_user",
        "current_status": get_lockdown_status(runner),
        "capability": capability.to_dict(),
    }


def open_lockdown_settings_fallback(runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    runner = runner or subprocess.run
    command = ["/usr/bin/open", LOCKDOWN_SETTINGS_URL]
    try:
        completed = runner(command, capture_output=True, text=True, timeout=5, check=False)
        return {
            "opened": int(getattr(completed, "returncode", 1) or 0) == 0,
            "command": command,
            "return_code": int(getattr(completed, "returncode", 1) or 0),
            "stdout": getattr(completed, "stdout", "") or "",
            "stderr": getattr(completed, "stderr", "") or "",
            "exception": "",
        }
    except Exception as exc:
        return {
            "opened": False,
            "command": command,
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "exception": str(exc),
        }


def _failure_reason(code: str, detail: str = "") -> str:
    return f"{code}: {detail}" if detail else code


def _classify_settings_fallback_failure(result: dict[str, Any], status_after: str) -> str:
    if result.get("exception"):
        return _failure_reason(FAILURE_INTERNAL_EXCEPTION, str(result.get("exception", "")))
    return_code = result.get("return_code")
    stderr = str(result.get("stderr", "") or "").strip()
    stdout = str(result.get("stdout", "") or "").strip()
    if return_code not in {0, None}:
        detail = stderr or stdout or f"/usr/bin/open returned {return_code}"
        if "not found" in detail.lower():
            return _failure_reason(FAILURE_SETTINGS_NOT_FOUND, detail)
        return _failure_reason(FAILURE_SYSTEM_REJECTED_REQUEST, detail)
    if status_after == "unknown":
        return _failure_reason(
            FAILURE_ACTIVATION_UNKNOWN,
            "Settings deep link opened but no public status API verified Lockdown Mode as enabled.",
        )
    return _failure_reason(
        FAILURE_USER_APPROVAL_REQUIRED,
        "Settings deep link opened; macOS still requires the user to turn on Lockdown Mode, authenticate if prompted, and restart.",
    )


def _recent_event_types(store: StateStore) -> set[str]:
    if not hasattr(store, "recent_background_monitor_events"):
        return set()
    try:
        return {str(event.event_type) for event in store.recent_background_monitor_events(limit=100)}  # type: ignore[attr-defined]
    except Exception:
        return set()


def critical_lockdown_trigger_reason(event: BackgroundMonitorEvent, store: StateStore | None = None) -> str:
    if event.simulated:
        return ""
    if event.severity != "critical" or event.confidence != "high":
        return ""
    if event.event_type == "protected_monitor_tamper_detected":
        return "Protected monitor tamper detected with critical severity and high confidence."
    if event.event_type in {"apple_security_forecast_urgent", "known_exploited_apple_vulnerability"}:
        metadata = {}
        try:
            metadata = json.loads(event.metadata_json or "{}")
        except json.JSONDecodeError:
            metadata = {}
        if metadata.get("applicability") in {"confirmed_applicable", "known_exploited_relevant"} or metadata.get("local_match") is True:
            return "Confirmed known-exploited Apple vulnerability applies locally."
        return ""
    event_set = _recent_event_types(store) if store is not None else set()
    event_set.add(str(event.event_type))
    if {"new_admin_user_detected", "execution_evidence_detected"}.issubset(event_set) or {"new_admin_user_detected", "unexpected_process_execution"}.issubset(event_set):
        return "New admin account and suspicious execution correlation reached critical confidence."
    if event_set.intersection({"launchdaemon_added", "launchagent_added", "persistence_item_created_high_risk"}) and event_set.intersection({"new_outbound_connection_detected", "localhost_hidden_port_detected", "vpn_connected"}):
        return "Persistence and suspicious network correlation reached critical confidence."
    if event_set.intersection({"monitor_blindness_detected", "detector_stopped", "heartbeat_stale", "db_not_updating"}) and event_set.intersection({"unexpected_process_execution", "execution_evidence_detected", "persistence_item_created_high_risk"}):
        return "Monitor blindness occurred during suspicious activity."
    if event_set.intersection({"remote_login_enabled", "screen_sharing_enabled"}) and event_set.intersection({"suspicious_login", "new_admin_user_detected", "unexpected_process_execution"}):
        return "Remote access was enabled unexpectedly with suspicious login or execution evidence."
    if event.event_type in {"major_security_event", "reverse_shell_pattern_detected", "possible_shellcode_memory_detected"}:
        return "Critical intrusion pattern confidence is high."
    return ""


def record_lockdown_action(store: StateStore, action: EmergencyLockdownAction) -> None:
    raw = store.get_background_monitor_state(ACTION_LOG_STATE_KEY, "[]")
    try:
        actions = json.loads(raw)
    except json.JSONDecodeError:
        actions = []
    if not isinstance(actions, list):
        actions = []
    actions.append(action.to_dict())
    store.set_background_monitor_state(ACTION_LOG_STATE_KEY, json.dumps(actions[-100:], sort_keys=True))
    store.set_background_monitor_state(LAST_ACTION_STATE_KEY, json.dumps(action.to_dict(), sort_keys=True))
    if action.error:
        store.set_background_monitor_state(LAST_FAILURE_STATE_KEY, action.error)


def record_lockdown_trace(store: StateStore, trace: LockdownModeTrace) -> None:
    raw = store.get_background_monitor_state(TRACE_LOG_STATE_KEY, "[]")
    try:
        traces = json.loads(raw)
    except json.JSONDecodeError:
        traces = []
    if not isinstance(traces, list):
        traces = []
    traces.append(trace.to_dict())
    store.set_background_monitor_state(TRACE_LOG_STATE_KEY, json.dumps(traces[-100:], sort_keys=True))
    store.set_background_monitor_state(LAST_TRACE_STATE_KEY, json.dumps(trace.to_dict(), sort_keys=True))
    if trace.failure_reason:
        store.set_background_monitor_state(LAST_FAILURE_STATE_KEY, trace.failure_reason)


def _create_emergency_snapshot(
    store: StateStore,
    event: BackgroundMonitorEvent,
    config: AuditConfig | None,
) -> tuple[bool, str, str]:
    try:
        center = SystemRecoveryCenter(store, config or AuditConfig())  # type: ignore[arg-type]
        snapshot = center.create_evidence_snapshot(
            assessment=center.incident_awareness_check(),
            reason=f"emergency_lockdown:{event.event_type}",
        )
        return True, str(snapshot.get("snapshot_path", "")), ""
    except Exception as exc:
        return False, "", _failure_reason(FAILURE_INTERNAL_EXCEPTION, f"Emergency evidence snapshot failed before activation: {exc}")


def _trace_and_action(
    store: StateStore,
    event: BackgroundMonitorEvent,
    *,
    policy_mode: str,
    trigger_reason: str,
    configured_policy_mode: str = "",
    status_before_payload: dict[str, Any],
    status_after_payload: dict[str, Any],
    dry_run: bool,
    action_attempted: str,
    snapshot_created: bool,
    snapshot_path: str,
    activation_supported: bool,
    automatic_activation_supported: bool,
    assisted_activation_supported: bool,
    activation_method: str,
    activation_path: str,
    requires_user_action: bool,
    settings_opened: bool,
    command: str = "",
    arguments: list[str] | None = None,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    exception: str = "",
    success: bool = False,
    failure_reason: str = "",
    notice_shown: bool = False,
) -> EmergencyLockdownAction:
    status_before = str(status_before_payload.get("status", "unknown"))
    status_after = str(status_after_payload.get("status", "unknown"))
    status_confidence = str(status_after_payload.get("confidence", "unknown"))
    trace = LockdownActivationTrace(
        timestamp=utc_now_iso(),
        trigger_event=event.event_type,
        trigger_event_id=event.event_id,
        confidence=event.confidence,
        policy_mode=policy_mode,
        configured_policy_mode=configured_policy_mode or policy_mode,
        dry_run=dry_run,
        action_attempted=action_attempted,
        snapshot_created=snapshot_created,
        snapshot_path=snapshot_path,
        lockdown_status_before=status_before,
        activation_supported=activation_supported,
        automatic_activation_supported=automatic_activation_supported,
        assisted_activation_supported=assisted_activation_supported,
        activation_method=activation_method,
        activation_path=activation_path,
        requires_user_action=requires_user_action,
        settings_opened=settings_opened,
        command=command,
        arguments=arguments or [],
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        exception=exception,
        verification_method="defaults_preference_probes",
        verification_result=str(status_after_payload.get("evidence", "")),
        lockdown_status_after=status_after,
        status_confidence=status_confidence,
        success=bool(success),
        failure_reason=failure_reason,
    )
    action = EmergencyLockdownAction(
        timestamp=utc_now_iso(),
        trigger_event_id=event.event_id,
        trigger_reason=trigger_reason,
        confidence=event.confidence,
        policy_mode=policy_mode,
        snapshot_created=snapshot_created,
        lockdown_status_before=status_before,
        lockdown_status_after=status_after,
        action_attempted=action_attempted,
        action_success=bool(success),
        configured_policy_mode=configured_policy_mode or policy_mode,
        error=failure_reason,
        user_visible_notice_shown=notice_shown,
        dry_run=dry_run,
        activation_method=activation_method,
        activation_supported=activation_supported,
        assisted_activation_supported=assisted_activation_supported,
        requires_user_action=requires_user_action,
        settings_opened=settings_opened,
        snapshot_path=snapshot_path,
        status_confidence=status_confidence,
    )
    record_lockdown_trace(store, trace)
    record_lockdown_action(store, action)
    return action


def dry_run_lockdown_response(
    store: StateStore,
    event: BackgroundMonitorEvent,
    *,
    policy_mode: str,
    trigger_reason: str,
    status_before_payload: dict[str, Any] | None = None,
    runner: Callable[..., Any] | None = None,
    notice_shown: bool = False,
) -> EmergencyLockdownAction:
    status_before_payload = status_before_payload or get_lockdown_status(runner)
    capability = lockdown_mode_capability(runner)
    return _trace_and_action(
        store,
        event,
        policy_mode=POLICY_DRY_RUN_ONLY,
        trigger_reason=trigger_reason or "dry-run critical event",
        configured_policy_mode=policy_mode,
        status_before_payload=status_before_payload,
        status_after_payload=status_before_payload,
        dry_run=True,
        action_attempted="dry_run",
        snapshot_created=True,
        snapshot_path="",
        activation_supported=capability.automatic_activation_supported,
        automatic_activation_supported=capability.automatic_activation_supported,
        assisted_activation_supported=capability.assisted_activation_supported,
        activation_method="dry_run",
        activation_path="",
        requires_user_action=False,
        settings_opened=False,
        success=False,
        failure_reason=_failure_reason(FAILURE_DRY_RUN, "Dry run only. No Lockdown Mode change was attempted."),
        notice_shown=notice_shown,
    )


def assist_user_lockdown_activation(
    store: StateStore,
    event: BackgroundMonitorEvent,
    *,
    policy_mode: str,
    trigger_reason: str,
    status_before_payload: dict[str, Any],
    config: AuditConfig | None = None,
    runner: Callable[..., Any] | None = None,
    notice_shown: bool = False,
    automatic_unsupported: bool = False,
) -> EmergencyLockdownAction:
    snapshot_created, snapshot_path, snapshot_error = _create_emergency_snapshot(store, event, config)
    if snapshot_error:
        return _trace_and_action(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=trigger_reason,
            status_before_payload=status_before_payload,
            status_after_payload=status_before_payload,
            dry_run=False,
            action_attempted="assist_user_failed_before_settings",
            snapshot_created=snapshot_created,
            snapshot_path=snapshot_path,
            activation_supported=False,
            automatic_activation_supported=False,
            assisted_activation_supported=True,
            activation_method="assist_user_settings_deep_link",
            activation_path=LOCKDOWN_SETTINGS_URL,
            requires_user_action=True,
            settings_opened=False,
            success=False,
            failure_reason=snapshot_error,
            notice_shown=notice_shown,
        )
    result = open_lockdown_settings_fallback(runner)
    status_after_payload = get_lockdown_status(runner)
    status_after = str(status_after_payload.get("status", "unknown"))
    settings_opened = bool(result.get("opened"))
    success = status_after == "enabled"
    if success:
        failure_reason = ""
    elif automatic_unsupported and settings_opened:
        failure_reason = _failure_reason(
            FAILURE_UNSUPPORTED_AUTOMATIC_ACTIVATION,
            "Automatic Lockdown Mode activation is not supported on this macOS version. User confirmation is required. The Lockdown Mode settings panel has been opened.",
        )
    else:
        failure_reason = _classify_settings_fallback_failure(result, status_after)
    return _trace_and_action(
        store,
        event,
        policy_mode=policy_mode,
        trigger_reason=trigger_reason,
        status_before_payload=status_before_payload,
        status_after_payload=status_after_payload,
        dry_run=False,
        action_attempted="assist_user",
        snapshot_created=snapshot_created,
        snapshot_path=snapshot_path,
        activation_supported=False,
        automatic_activation_supported=False,
        assisted_activation_supported=True,
        activation_method="assist_user_settings_deep_link",
        activation_path=LOCKDOWN_SETTINGS_URL,
        requires_user_action=not success,
        settings_opened=settings_opened,
        command=str(result["command"][0]) if result.get("command") else "",
        arguments=[str(item) for item in result.get("command", [])[1:]],
        return_code=result.get("return_code"),
        stdout=str(result.get("stdout", "")),
        stderr=str(result.get("stderr", "")),
        exception=str(result.get("exception", "")),
        success=success,
        failure_reason=failure_reason,
        notice_shown=notice_shown,
    )


def attempt_lockdown_activation(
    store: StateStore,
    event: BackgroundMonitorEvent,
    *,
    policy_mode: str,
    trigger_reason: str,
    status_before_payload: dict[str, Any],
    config: AuditConfig | None = None,
    runner: Callable[..., Any] | None = None,
    notice_shown: bool = False,
) -> EmergencyLockdownAction:
    capability = lockdown_mode_capability(runner)
    if not capability.automatic_activation_supported:
        return assist_user_lockdown_activation(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=trigger_reason,
            status_before_payload=status_before_payload,
            config=config,
            runner=runner,
            notice_shown=notice_shown,
            automatic_unsupported=True,
        )
    snapshot_created, snapshot_path, snapshot_error = _create_emergency_snapshot(store, event, config)
    if snapshot_error:
        return _trace_and_action(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=trigger_reason,
            status_before_payload=status_before_payload,
            status_after_payload=status_before_payload,
            dry_run=False,
            action_attempted="attempt_activation",
            snapshot_created=snapshot_created,
            snapshot_path=snapshot_path,
            activation_supported=True,
            automatic_activation_supported=True,
            assisted_activation_supported=capability.assisted_activation_supported,
            activation_method="automatic_public_api",
            activation_path="",
            requires_user_action=False,
            settings_opened=False,
            success=False,
            failure_reason=snapshot_error,
            notice_shown=notice_shown,
        )
    status_after_payload = get_lockdown_status(runner)
    success = str(status_after_payload.get("status", "unknown")) == "enabled"
    return _trace_and_action(
        store,
        event,
        policy_mode=policy_mode,
        trigger_reason=trigger_reason,
        status_before_payload=status_before_payload,
        status_after_payload=status_after_payload,
        dry_run=False,
        action_attempted="attempt_activation",
        snapshot_created=snapshot_created,
        snapshot_path=snapshot_path,
        activation_supported=True,
        automatic_activation_supported=True,
        assisted_activation_supported=capability.assisted_activation_supported,
        activation_method="automatic_public_api",
        activation_path="",
        requires_user_action=False,
        settings_opened=False,
        success=success,
        failure_reason="" if success else _failure_reason(FAILURE_VERIFICATION_FAILED, "Automatic activation did not verify Lockdown Mode as enabled."),
        notice_shown=notice_shown,
    )


def enable_lockdown_with_user_policy(
    store: StateStore,
    event: BackgroundMonitorEvent,
    *,
    config: AuditConfig | None = None,
    runner: Callable[..., Any] | None = None,
    notice_callback: Callable[[str], bool] | None = None,
    dry_run: bool = False,
) -> EmergencyLockdownAction:
    policy = load_policy(store)
    policy_mode = str(policy.get("mode", POLICY_DISABLED))
    reason = critical_lockdown_trigger_reason(event, store)
    status_before_payload = get_lockdown_status(runner)
    status_before = str(status_before_payload.get("status", "unknown"))
    notice_shown = False
    if notice_callback and (reason or dry_run):
        try:
            notice_shown = bool(notice_callback(reason or "Dry-run critical event policy evaluation."))
        except Exception:
            notice_shown = False

    if not reason and not dry_run:
        return EmergencyLockdownAction(
            timestamp=utc_now_iso(),
            trigger_event_id=event.event_id,
            trigger_reason="",
            confidence=event.confidence,
            policy_mode=policy_mode,
            snapshot_created=False,
            lockdown_status_before=status_before,
            lockdown_status_after=status_before,
            action_attempted="none",
            action_success=False,
            error="Event did not meet critical/high-confidence lockdown trigger policy.",
            user_visible_notice_shown=notice_shown,
            dry_run=False,
        )
    if dry_run:
        return dry_run_lockdown_response(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=reason,
            status_before_payload=status_before_payload,
            runner=runner,
            notice_shown=notice_shown,
        )
    if policy_mode == POLICY_DISABLED:
        action = EmergencyLockdownAction(
            timestamp=utc_now_iso(),
            trigger_event_id=event.event_id,
            trigger_reason=reason,
            confidence=event.confidence,
            policy_mode=policy_mode,
            snapshot_created=False,
            lockdown_status_before=status_before,
            lockdown_status_after=status_before,
            action_attempted="none",
            action_success=False,
            error=_failure_reason(FAILURE_UNKNOWN, "Emergency Lockdown response is disabled by policy."),
            user_visible_notice_shown=notice_shown,
            dry_run=False,
            status_confidence=str(status_before_payload.get("confidence", "unknown")),
        )
        record_lockdown_action(store, action)
        return action
    if policy_mode in {POLICY_RECOMMEND_ONLY, POLICY_ASK}:
        action = EmergencyLockdownAction(
            timestamp=utc_now_iso(),
            trigger_event_id=event.event_id,
            trigger_reason=reason,
            confidence=event.confidence,
            policy_mode=policy_mode,
            snapshot_created=False,
            lockdown_status_before=status_before,
            lockdown_status_after=status_before,
            action_attempted="recommend_only",
            action_success=False,
            error=_failure_reason(FAILURE_USER_APPROVAL_REQUIRED, "Policy is Recommend Only; no activation was attempted."),
            user_visible_notice_shown=notice_shown,
            dry_run=False,
            requires_user_action=True,
            status_confidence=str(status_before_payload.get("confidence", "unknown")),
        )
        record_lockdown_action(store, action)
        return action
    if policy_mode == POLICY_ASSIST_USER:
        return assist_user_lockdown_activation(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=reason,
            status_before_payload=status_before_payload,
            config=config,
            runner=runner,
            notice_shown=notice_shown,
        )
    if policy_mode in {POLICY_ATTEMPT_ACTIVATION, POLICY_AUTO, POLICY_AUTO_AFTER_SNAPSHOT}:
        return attempt_lockdown_activation(
            store,
            event,
            policy_mode=policy_mode,
            trigger_reason=reason,
            status_before_payload=status_before_payload,
            config=config,
            runner=runner,
            notice_shown=notice_shown,
        )
    return EmergencyLockdownAction(
        timestamp=utc_now_iso(),
        trigger_event_id=event.event_id,
        trigger_reason=reason,
        confidence=event.confidence,
        policy_mode=policy_mode,
        snapshot_created=False,
        lockdown_status_before=status_before,
        lockdown_status_after=status_before,
        action_attempted="none",
        action_success=False,
        error=_failure_reason(FAILURE_UNKNOWN, f"Unknown policy mode: {policy_mode}"),
        user_visible_notice_shown=notice_shown,
        dry_run=False,
        status_confidence=str(status_before_payload.get("confidence", "unknown")),
    )
