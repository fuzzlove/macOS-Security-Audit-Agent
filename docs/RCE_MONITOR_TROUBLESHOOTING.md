# RCE monitor troubleshooting

- `NO_DATA`: confirm the existing system LaunchDaemon is loaded, the shared database path is correct, and a heartbeat is fresh.
- `ACTIVE_DEGRADED`: expected without Endpoint Security entitlement; inspect documented gaps rather than interpreting this as failure-free coverage.
- `RCE_MONITOR_HEALTH_FAILURE`: run `msaa rce-monitor health`, inspect redacted daemon logs, verify fixed executable permissions, disk space, SQLite integrity, and config ownership.
- Config reload failure: run `config-validate`; the last known valid configuration remains active.
- CVE cache stale/absent: runtime detection continues. Import only administrator-approved normalized data; never fabricate a CVE record.
- Chain failure: stop mutation/export activity, preserve a copy of the database and logs, and investigate. Do not repair by deleting records.

Service recovery uses the existing MSAA installer and launchd label. Do not manually weaken TCC, SIP, or code-signing requirements. After recovery verify a fresh cycle, sensor mode, queue health, and evidence chain.
