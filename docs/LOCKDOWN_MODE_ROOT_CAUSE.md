# Lockdown Mode Root Cause

Date: 2026-06-06

## Finding

Lockdown Mode did not become enabled because Mac Audit Agent does not have a supported programmatic activation method. The current activation path opens the macOS Lockdown Mode settings pane with `/usr/bin/open`. That is user assistance only. It is not an activation API, and a zero return code only proves that macOS accepted the request to open System Settings.

Apple documents Lockdown Mode activation on Mac as an interactive System Settings workflow: open Privacy & Security, choose Lockdown Mode, select Turn On, select Turn On & Restart, and enter the login password if prompted. Apple also states that Lockdown Mode is not configurable by Mobile Device Management administrators.

Primary root cause: `unsupported_api`.

Contributing causes:

- `user_approval_required`: macOS requires explicit user action.
- `verification_failed` or `activation_unknown`: the app cannot prove enabled state unless the independent status probe returns enabled after the attempt.
- Prior implementation risk: treating `/usr/bin/open` return code as meaningful activation progress could make the workflow look successful even though the state did not change.

## Current Activation Path

Code path:

- `mac_audit_agent/monitor.py:_evaluate_emergency_lockdown_policy`
- `mac_audit_agent/emergency_lockdown.py:enable_lockdown_with_user_policy`
- `mac_audit_agent/emergency_lockdown.py:can_enable_lockdown`
- `mac_audit_agent/emergency_lockdown.py:open_lockdown_settings_fallback`

Attempted command:

```text
/usr/bin/open x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?LockdownMode
```

What this does:

- Opens or attempts to open System Settings.
- Does not click Turn On.
- Does not authenticate.
- Does not restart.
- Does not prove Lockdown Mode changed.

Supported status:

- The deep link is not a public Apple Lockdown Mode activation API.
- It is only a fallback to assist the user.

## Current Detection Path

Code path:

- `mac_audit_agent/emergency_lockdown.py:get_lockdown_status`

Current probes:

```text
/usr/bin/defaults read com.apple.security LockdownMode
/usr/bin/defaults read com.apple.Safari LockdownMode
/usr/bin/defaults read com.apple.Safari LockdownModeEnabled
```

Detection status:

- These are best-effort preference probes.
- They are not documented by Apple as a stable public Lockdown Mode status API.
- If the probes do not prove enabled or disabled, status is `unknown`.

Local probe result on 2026-06-06:

- `com.apple.security LockdownMode`: domain/default pair does not exist.
- `com.apple.Safari LockdownMode`: domain/default pair does not exist.
- `com.apple.Safari LockdownModeEnabled`: domain/default pair does not exist.
- Result: Lockdown Mode was not verified as enabled by the current detection path.

Status output now includes:

- `status`: `enabled`, `disabled`, or `unknown`
- `confidence`: `medium`, `low`, or `unknown`
- `evidence`: the probe or reason supporting the result

Missing preference keys are not treated as a successful verification and are not treated as high-confidence disabled state. If no probe proves state, the UI must show: `Lockdown Mode status could not be confirmed.`

## Current Verification Path

The workflow now verifies independently after any activation attempt:

1. Capture `lockdown_status_before`.
2. Attempt the selected path.
3. Capture command, arguments, return code, stdout, stderr, and exception.
4. Re-run `get_lockdown_status`.
5. Capture `lockdown_status_after`.
6. Report success only if independent verification returns `enabled`.

The app does not trust:

- return code
- absence of exception
- `open` command success
- internal success booleans

If state is unchanged or unknown, the action is failed and classified.

## Current Policy Path

Code path:

- `load_policy`
- `save_policy`
- `enable_lockdown_with_user_policy`

Modes:

- `disabled`: no activation.
- `recommend_only`: no activation.
- `assist_user`: open settings fallback only.
- `attempt_activation`: create evidence snapshot, assess capability, then attempt only a verified supported automatic method. Because none is available, it downgrades to assisted activation, opens Settings, marks `requires_user_action=true`, and records `unsupported_automatic_activation`.
- `managed_environment`: documented mode, but Apple does not expose MDM activation for Lockdown Mode.

Default:

- `recommend_only`

## Current Trigger Path

Code path:

- `BackgroundMonitorService.record_monitor_event`
- `BackgroundMonitorService._evaluate_emergency_lockdown_policy`
- `critical_lockdown_trigger_reason`

This audit did not add trigger conditions. Trigger logic is not the root cause. The trigger path can execute and the response path can run while Lockdown Mode remains disabled because activation is unsupported.

## Current UI Path

Existing section:

- Security Response > Emergency Lockdown

It now displays:

- Current Status
- Last Attempt
- Last Trigger
- Last Failure
- Activation Method
- Verification Method
- Failure Reason
- Full Error through copied diagnostics

Button:

- Copy Lockdown Diagnostics

Dry Run:

- Emergency Lockdown Dry Run shows the workflow without changing system state.

## Current Logging Path

Persistent state keys:

- `emergency_lockdown_actions_json`
- `emergency_lockdown_last_action_json`
- `emergency_lockdown_traces_json`
- `emergency_lockdown_last_trace_json`
- `emergency_lockdown_last_failure`

Trace model:

- `LockdownActivationTrace`

Fields:

- `timestamp`
- `trigger_event`
- `trigger_event_id`
- `confidence`
- `policy_mode`
- `dry_run`
- `action_attempted`
- `snapshot_created`
- `snapshot_path`
- `lockdown_status_before`
- `activation_supported`
- `automatic_activation_supported`
- `assisted_activation_supported`
- `activation_method`
- `activation_path`
- `requires_user_action`
- `settings_opened`
- `command`
- `arguments`
- `return_code`
- `stdout`
- `stderr`
- `exception`
- `verification_method`
- `verification_result`
- `lockdown_status_after`
- `status_confidence`
- `success`
- `failure_reason`

No silent activation failures are allowed after this change.

## Failure Classification

Supported classifications:

- `unsupported_os`
- `unsupported_api`
- `missing_permission`
- `user_approval_required`
- `verification_failed`
- `activation_failed`
- `activation_unknown`
- `settings_not_found`
- `system_rejected_request`
- `configuration_profile_required`
- `managed_environment_required`
- `internal_exception`
- `unknown`

Common production result:

```text
unsupported_automatic_activation: Automatic Lockdown Mode activation is not supported on this macOS version. User confirmation is required. The Lockdown Mode settings panel has been opened.
```

If System Settings rejects the URL:

```text
system_rejected_request: <stderr/stdout/return code detail>
```

If the user explicitly clicks the dry-run button:

```text
dry_run: Dry run only. No Lockdown Mode change was attempted.
```

That result must never be produced by `attempt_activation` unless the caller explicitly requested `dry_run=True`. Dry-run traces use `policy_mode=dry_run_only` and store the saved policy separately as `configured_policy_mode`, so a dry-run button press cannot look like the real `attempt_activation` policy path silently dry-ran.

## Evidence Preservation

Before `attempt_activation`, the app creates an emergency evidence snapshot through:

- `SystemRecoveryCenter.create_evidence_snapshot`

Snapshot contents include:

- database export
- monitor events
- active notes
- forecast state
- persistence inventory
- network inventory
- running process payload when available
- scan artifacts when available

If snapshot creation fails, activation does not proceed and the error is classified as `internal_exception`.

## Alert Visibility

If an activation path is attempted and final verification does not prove Lockdown Mode is enabled, the app creates a visible critical overlay event:

Title:

```text
Emergency Lockdown Failed
```

Body:

```text
Automatic Lockdown Mode activation was requested but could not be verified.
Reason: <classified reason>
```

Buttons:

- View Diagnostics
- Open Hardening Center
- Create Evidence Snapshot

If `attempt_activation` finds automatic activation unsupported and opens Settings as assisted activation, the app creates this visible critical overlay event:

Title:

```text
Lockdown Mode Requires User Action
```

Body:

```text
A critical security event triggered Emergency Lockdown policy, but macOS requires user confirmation to enable Lockdown Mode. The settings panel has been opened. Complete Turn On & Restart to enable Lockdown Mode.
```

Buttons:

- Open Lockdown Settings
- View Evidence Snapshot
- Acknowledge

## Direct Answers

1. Was activation attempted?
   - A supported activation was not attempted because no supported public activation method is available. The fallback assistance path was attempted when policy allowed it.

2. How was activation attempted?
   - Automatic activation is not attempted unless a verified supported method exists. With current macOS support, the app downgrades to assisted activation and runs `/usr/bin/open` against a System Settings deep link. This is not activation; it only opens settings.

3. What failed?
   - Automatic activation failed because macOS requires interactive user approval and restart. Verification did not prove enabled state afterward.

4. Is activation supported?
   - Programmatic activation is not currently supported by a documented public Apple API, command-line tool, configuration profile, or MDM command.

5. Is activation verifiable?
   - Only partially. The app has best-effort local probes, but no stable public Apple status API was identified. Therefore unknown status remains possible and must not be treated as success.

6. Did the state actually change?
   - The app now records `lockdown_status_before` and `lockdown_status_after`. If `lockdown_status_after` is not `enabled`, the state did not verify as changed and the action fails.

## Final Root Cause

The failure is not trigger logic.

The failure is not alert logic.

The failure is not a missing admin escalation inside Mac Audit Agent.

The failure is an unsupported activation path: the implementation could only open System Settings, while Apple requires the user to enable Lockdown Mode interactively and restart. The app must never claim Lockdown Mode is enabled unless independent verification returns enabled.

Corrected behavior:

- Dry-run is only used when explicitly requested.
- `attempt_activation` does not silently become dry-run.
- Settings deep link is labeled `assist_user_settings_deep_link`.
- Unsupported automatic activation is classified as `unsupported_automatic_activation`.
- Assisted activation records `requires_user_action=true` and `settings_opened=true` when the settings panel opens.

## Sources

- Apple Support, About Lockdown Mode: https://support.apple.com/105120
- Apple Support, Lock down your Mac if you are targeted by a cyberattack: https://support.apple.com/guide/mac-help/ibrw66f4e191/mac
- Apple Platform Security, Lockdown Mode security for Apple devices: https://support.apple.com/guide/security/lockdown-mode-security-sec2437264f0/web
