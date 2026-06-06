# Lockdown Mode Analysis

## Summary

Root cause: activation did not fail because of trigger logic. The policy reached the activation path, but the implementation only opened the macOS Lockdown Mode settings pane. Apple documents Lockdown Mode activation as an interactive user flow that requires clicking through System Settings, entering the user password if prompted, and restarting. Apple does not document a public command-line API, app API, configuration profile payload, or MDM command that lets Mac Audit Agent enable Lockdown Mode automatically.

The previous implementation incorrectly allowed the settings fallback to report `action_success=True` when `/usr/bin/open` returned `0`. That return code only proves that macOS accepted the request to open System Settings. It does not prove Lockdown Mode was enabled.

## Phase 1: Capability Assessment

1. How is Lockdown Mode currently detected?
   - `mac_audit_agent/emergency_lockdown.py:get_lockdown_status()` probes these preference keys with `/usr/bin/defaults read`:
     - `com.apple.security LockdownMode`
     - `com.apple.Safari LockdownMode`
     - `com.apple.Safari LockdownModeEnabled`
   - If a probe returns `1`, `true`, `TRUE`, `YES`, or `yes`, the app reports `enabled`.
   - If a probe returns another value, the app reports `disabled`.
   - If no probe returns usable evidence, the app reports `unknown`.

2. How is Lockdown Mode currently enabled?
   - It is not programmatically enabled.
   - The only implemented path is a settings deep-link:
     - `/usr/bin/open x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?LockdownMode`
   - The app now treats that as user assistance, not proof of activation.

3. What API is being used?
   - Status: `/usr/bin/defaults read` preference probes.
   - Activation fallback: `/usr/bin/open` with a System Settings URL.

4. Is it public?
   - `/usr/bin/open` and System Settings are public user-facing mechanisms.
   - The exact `x-apple.systempreferences:` deep-link target is not documented by Apple as a stable Lockdown Mode activation API.
   - The preference keys are not documented by Apple as a stable Lockdown Mode status API.

5. Is it private?
   - The current code does not call a private framework or private binary to enable Lockdown Mode.
   - The preference-key probes are implementation guesses, not documented public status APIs.

6. Is it supported?
   - Opening System Settings for the user is supportable as an assistive fallback.
   - Treating Settings launch as automatic Lockdown Mode enablement is not supported.
   - Programmatic enablement is not supported by any Apple-documented public mechanism found during this analysis.

7. Does it require user interaction?
   - Yes. Apple documents the Mac flow as: System Settings > Privacy & Security > Lockdown Mode > Turn On > Turn on Lockdown Mode > Turn On & Restart.

8. Does it require admin privileges?
   - Apple says the user may need to enter the user password. The app must not bypass this.

9. Does it require logout/restart?
   - Yes. Apple documents the final Mac activation action as `Turn On & Restart`.

10. Is programmatic enablement actually possible?
   - No supported public programmatic enablement path was identified.
   - Current app behavior must therefore be `Recommend Only` or `Assist User` unless a verified public activation method is later found.

## Local Proof

Local probe results on the development Mac:

| Probe | Result |
| --- | --- |
| `/usr/bin/defaults read com.apple.security LockdownMode` | Exit `1`; domain/default pair does not exist |
| `/usr/bin/defaults read com.apple.Safari LockdownMode` | Exit `1`; domain/default pair does not exist |
| `/usr/bin/defaults read com.apple.Safari LockdownModeEnabled` | Exit `1`; domain/default pair does not exist |
| `sw_vers` | macOS `26.4.1`, build `25E253` |

Conclusion: the previous status detector cannot prove enabled or disabled on this Mac. It must report `unknown` unless a probe returns explicit evidence.

## Phase 2: Execution Trace

`LockdownModeTrace` has been added and is stored in background monitor state under:

- `emergency_lockdown_traces_json`
- `emergency_lockdown_last_trace_json`

Fields:

- `timestamp`
- `trigger_event`
- `policy_mode`
- `lockdown_status_before`
- `enable_attempted`
- `enable_method`
- `permission_level`
- `command_executed`
- `return_code`
- `stdout`
- `stderr`
- `exception`
- `lockdown_status_after`
- `success`
- `failure_reason`

Every triggered emergency-lockdown policy evaluation now records a trace. The trace records the command used for the settings fallback, its return code, stdout, stderr, exception, status before, status after, and whether verification actually proved success.

## Phase 3: Supported Activation Paths

### Method A: Supported Public Mechanism

- Mechanism: User opens System Settings and enables Lockdown Mode interactively.
- Reliability: High when completed by the user.
- Supported status: Supported by Apple.
- User approval requirements: Required.
- OS compatibility: macOS Ventura / macOS 13 or later.
- Restart requirement: Required.
- App behavior: `Assist User` can open the relevant settings and show instructions.

### Method B: Settings Deep-Link

- Mechanism: `/usr/bin/open x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?LockdownMode`
- Reliability: Medium. It may open the intended settings area, but it does not click buttons, authenticate, or restart.
- Supported status: Acceptable as a user-assistance fallback; not a supported activation API.
- User approval requirements: Required.
- OS compatibility: System Settings URL behavior can change across macOS versions.
- App behavior: May be used only as fallback guidance. Success must remain false until independent verification reports `enabled`.

### Method C: Managed Configuration/Profile

- Mechanism: Configuration profile payload.
- Reliability: Not available for enabling Lockdown Mode.
- Supported status: Apple states Lockdown Mode is not configurable by MDM administrators.
- User approval requirements: Not applicable.
- OS compatibility: Not applicable.
- App behavior: Document only. Do not generate a profile claiming to enable Lockdown Mode.

### Method D: MDM-Supported Path

- Mechanism: MDM command or declarative management path.
- Reliability: Not available for enabling Lockdown Mode.
- Supported status: Apple states Lockdown Mode is not a configurable MDM option. Devices already enrolled before Lockdown Mode remain managed, and administrators can still install and remove profiles on those already managed devices.
- User approval requirements: Not applicable for activation because activation is not exposed as MDM control.
- OS compatibility: Not applicable.
- App behavior: `Managed Environment` mode should recommend contacting the managing organization and document that Mac Audit Agent cannot force Lockdown Mode through MDM.

### Method E: Unsupported/Private Path

- Mechanism: Private preferences, private frameworks, UI scripting, or prompt automation.
- Reliability: Unknown and OS-fragile.
- Supported status: Unsupported.
- User approval requirements: Would risk bypassing or faking user consent.
- OS compatibility: Unknown.
- App behavior: Prohibited. Do not implement unsupported hacks, do not click prompts, and do not write private preference keys.

## Phase 4: Policy Modes

`LockdownResponseMode` now defines:

- `Disabled`
- `Recommend Only`
- `Assist User`
- `Attempt Activation`
- `Managed Environment`

Default: `Recommend Only`.

`Attempt Activation` must not claim success unless the app verifies that Lockdown Mode is enabled after the attempt. Because no supported programmatic activation method is currently verified, the app falls back to user assistance and records the exact failure reason.

## Phase 5: Verification

After any activation path:

1. Record `lockdown_status_before`.
2. Execute only the selected supported or fallback method.
3. Record command output and exceptions.
4. Re-check Lockdown Mode status independently.
5. Record `lockdown_status_after`.
6. Treat the action as failed unless `lockdown_status_after == enabled`.

The app no longer trusts `/usr/bin/open` return code as activation success.

## Phase 6: Fallback Workflow

If automatic enablement is unsupported, the user-facing reason must be:

Emergency Hardening Required

Lockdown Mode could not be enabled automatically.

Reason:
No supported public command-line API or MDM payload for enabling Lockdown Mode is documented by Apple. macOS requires the user to enable it in System Settings, authenticate if prompted, and restart.

Provide:

- Open Relevant Settings
- Step-by-step instructions:
  1. Open System Settings.
  2. Open Privacy & Security.
  3. Scroll to Lockdown Mode.
  4. Click Turn On.
  5. Click Turn on Lockdown Mode.
  6. Click Turn On & Restart.
  7. Enter the user password if prompted.
- Evidence snapshot creation before guidance when policy is triggered.

## Phase 7: Managed Environment Support

Apple documents two important managed-device facts:

- New configuration profiles cannot be installed and new MDM enrollment cannot occur while Lockdown Mode is already enabled.
- Devices enrolled in MDM before Lockdown Mode is enabled remain managed.
- Lockdown Mode is not configurable by MDM administrators.

Therefore:

- Configuration profiles are not a supported activation path.
- MDM is not a supported activation path.
- Managed-environment mode should provide documentation, evidence capture, and escalation guidance to the organization, not claim enforcement.

## Phase 8: Acceptance Criteria Status

1. Lockdown Mode status can be reliably detected.
   - Partial. The app now refuses to overstate status when public proof is unavailable. A stable public status API was not found.
2. Every activation attempt is audited.
   - Implemented with `LockdownModeTrace`.
3. Failure reasons are visible.
   - Implemented through trace failure reasons and `emergency_lockdown_last_failure`.
4. Success is independently verified.
   - Implemented. Success requires post-attempt status `enabled`.
5. Unsupported activation paths are documented.
   - Implemented in this document.
6. Users are never falsely told Lockdown Mode was enabled.
   - Implemented by removing success based only on Settings launch.
7. Managed-environment options are documented separately.
   - Implemented in Phase 7.

## Root Cause Classification

- Trigger logic: Not the proven failure.
- Permissions: User password and restart are required by the supported Apple flow, but the app did not reach a real activation API.
- Unsupported API: Primary root cause. No supported public automatic activation API was identified.
- OS limitation: Contributing cause. macOS exposes Lockdown Mode as an interactive Settings workflow.
- Verification bug: Primary implementation bug. The app treated opening Settings as success.
- Activation bug: Primary implementation bug. The app had no actual supported activation method.

## Sources

- Apple Support, About Lockdown Mode: https://support.apple.com/en-us/105120
- Apple Support, Lock down your Mac if you're targeted by a cyberattack: https://support.apple.com/guide/mac-help/ibrw66f4e191/mac
- Apple Platform Security, Lockdown Mode security for Apple devices: https://support.apple.com/guide/security/lockdown-mode-security-sec2437264f0/web
- Apple Platform Deployment, Intro to device management profiles: https://support.apple.com/guide/deployment/intro-to-mdm-profiles-depc0aadd3fe/web
