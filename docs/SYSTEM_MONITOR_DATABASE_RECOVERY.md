# System Monitor Database Recovery

`database disk image is malformed` is a SQLite integrity failure, not a normal service restart condition. Repeated restart or repair commands cannot fix damaged database pages and may create a launchd restart loop.

Run the read-only check first:

```sh
python3 scripts/repair_system_monitor_database.py --check
```

Authorized recovery requires administrator access because the database and LaunchDaemon are root-owned:

```sh
sudo python3 scripts/repair_system_monitor_database.py
```

The recovery workflow unloads the daemon, copies the database and sidecars into a timestamped evidence directory, records the original SHA-256, runs SQLite `.recover` into a separate database, applies current MSAA schema migrations, requires `PRAGMA quick_check=ok`, atomically preserves the corrupt original, installs the validated database with restricted ownership, writes a recovery receipt, bootstraps the existing LaunchDaemon, and verifies kickstart success. It does not claim every damaged row is recoverable.

The tool also distinguishes a damaged main image from a clean main image paired with a corrupt WAL/SHM sidecar. In the latter case it preserves and detaches only the sidecars, validates ordinary (non-immutable) database access, and restarts the service without unnecessarily rebuilding the clean main image. Sidecars from an older database generation are archived at the replacement boundary so they cannot be attached to a recovered image.

Do not delete `*.corrupt-*` or the recovery-evidence directory until retention and incident-review requirements permit it. After recovery, verify heartbeat freshness, detector cycles, notifier polling, and event delivery in Monitor Settings.

The shared integrity key is intentionally not writable by desktop users. For the system database its required ownership and mode are `root:admin 0640`: the root daemon can create and update tamper-evident records, while authorized local administrators can read the key to verify and display those records. The user-database key remains owner-only `0600`. Group-write or any world access is rejected.
