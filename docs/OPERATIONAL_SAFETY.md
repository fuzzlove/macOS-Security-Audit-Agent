# Operational Safety

## Safe Defaults

- no destructive cleanup by default
- no aggressive scans by default
- no packet capture by default
- no system daemon install by default
- no remediation by default

## Incident Handling

If intrusion evidence exists:

- preserve logs and evidence
- create an evidence snapshot before cleanup
- review the timeline before taking destructive action
- do not delete logs automatically

## Notification Safety

- visible alerts are rate-limited
- repeated events should group instead of spamming
- high/critical alerts may persist until acknowledged

## Health and Failure Handling

- failures should be logged
- the UI should show degraded/broken states instead of failing silently
- monitor and notifier failures should be visible
