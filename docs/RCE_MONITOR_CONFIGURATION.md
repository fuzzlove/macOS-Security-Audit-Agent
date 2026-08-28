# RCE monitor configuration reference

`config/rce-monitor.json` is schema 1.0. It defaults to enabled, high sensitivity, monitor-only behavior, a bounded 2,048-event analysis queue, 30-second correlation window, hourly inventory, seven-day CVE freshness, and root-only mutation. Unknown schema versions, invalid sensitivity, oversized files, and unsafe queue sizes are rejected atomically.

`enabled_sensors` declares available integrations; it does not make unavailable telemetry healthy. `framework_versions` and ATT&CK paths are administrator-supplied to avoid stale or invented mappings. Retention fields express policy but automated deletion is not enabled until signed retention-boundary evidence exists. External export is disabled by omission; the privileged daemon has no feed or telemetry upload client.
