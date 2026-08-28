# Process Injection Troubleshooting

- `DEGRADED_POLLING`: expected without an entitled native sensor; do not interpret missing task/thread events as absence.
- ATT&CK unavailable/stale: mappings remain unverified/stale while deterministic primitive detection continues.
- No telemetry: verify daemon heartbeat, sensor permissions, configuration, queue and database health.
- Evidence failure: preserve logs, verify directory ownership/space, policy classification and encryption provider. Never bypass protected-process policy.
- Integrity failure: stop exports, preserve the database/bundle, verify hashes/custody, and open an incident.
- PID ambiguity: require boot and start-time identity before grouping.

Use `status`, `sensors-status`, `rules-validate`, `events-show`, `events-timeline`, `events-graph`, and `investigate` before disposition.
