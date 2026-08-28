# Force Keyword Handling Audit

MSAA now treats `force` as an explicit safe retry/cache-bypass signal, not as a security override.

## Canonical Semantics

Supported syntax:

- `--force`
- `-f`
- `force`
- `force=true`
- `force=false`

Safe meaning:

- bypass cache
- rerun local checks
- retry safe repairs
- refresh stale data
- rebuild generated manifests through existing validation
- rerun diagnostics from scratch

Unsafe meanings rejected:

- silently trust modified files
- bypass integrity verification
- delete logs, databases, reports, or evidence
- disable security controls
- suppress alerts
- perform destructive remediation
- authorize external scanning

## Command Inventory

| Command | Current force support | Accepted syntax | Safe force behavior | Unsafe force behavior | Confirmation |
| --- | --- | --- | --- | --- | --- |
| `macos-security-audit-agent --safe-scan` | supported | `--force`, `-f`, `force`, `force=true/false` | ignores previous scan result and runs a fresh safe scan | does not enable destructive scan behavior | no |
| `macos-security-audit-agent --aggressive-scan` | supported | same | reruns the selected local scan fresh | does not authorize external scans | existing aggressive scan controls apply |
| `macos-security-audit-agent --report` / `--json-report` | supported as refresh/diagnostics | same | regenerates output from latest or requested scan | does not delete evidence packages | overwrite behavior remains caller-controlled by output path |
| `macos-security-audit-agent persistence scan/export/doctor` | supported | same | reruns Persistence Intelligence from fresh local data | rejects forced baseline delete | baseline delete blocked with force |
| `python3 -m mac_audit_agent.rootkit_detection.scan` | supported | same | reruns read-only rootkit suspect review | no unload/delete/kill/external scan | no |
| `python3 -m mac_audit_agent.user_notifier_doctor --repair` | supported | same | retries plist validation/bootstrap/kickstart repair | does not delete logs or databases | repair workflow validation applies |
| `python3 -m mac_audit_agent.integrity.release_verify` | supported | same | reruns verification from current files | does not trust new hashes or regenerate manifest | no |
| `python3 -m mac_audit_agent.integrity.release_sign` | supported | same | retries manifest/signing after normal validation | does not bypass dirty-tree/version/signature safeguards | normal signing safeguards apply |
| `integrity trust --force` | rejected | same | none | force cannot trust modified files | rejected |
| `delete evidence --force` | rejected | same | none | force cannot delete evidence | rejected |
| `suppress alerts --force` | rejected | same | none | force cannot suppress alerts | rejected |
| `external scan --force` | rejected | same | none | force cannot authorize external scanning | rejected |

## Diagnostics

Every accepted or rejected force action is logged to:

`~/Library/Logs/MacAuditAgent/actions.log`

The log records timestamp, user, command, force scope, reason, safety flags, result, and rejection reason when applicable.

## Required Messages

- Supported force: `Force enabled: cached data will be bypassed and the operation will run fresh.`
- Unsupported force: `Force is not supported for this command.`
- Unsafe force: `Force was refused because this action could alter security state or evidence.`
- Force alone: `Specify what to force. Examples: scan --force, refresh --force, repair-notifier --force.`
