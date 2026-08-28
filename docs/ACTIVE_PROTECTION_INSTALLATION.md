# Active Protection Installation

Run the GUI as the logged-in user. Review the proposed LaunchDaemon, user notifier LaunchAgent, runtime database, settings synchronization, installed manifest, heartbeat, alert verification, and evidence path before authorizing the headless installer.

```console
python3.12 -m mac_audit_agent.protection doctor --json
sudo python3.12 -m mac_audit_agent.protection install --mode protected --with-system-daemon --with-user-notifier --apply-current-settings --verify --verbose
sudo python3.12 -m mac_audit_agent.protection repair --mode protected --repair-system-daemon --repair-user-notifier --repair-settings-sync --verify --verbose
```

No silent privilege escalation occurs. Missing Endpoint Security entitlement or Full Disk Access results in an explicit degraded observation state, not a fully protected claim.
