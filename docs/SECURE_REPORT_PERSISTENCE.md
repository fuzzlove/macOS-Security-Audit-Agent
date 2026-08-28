# Secure report persistence

## Root cause and boundary

The intrusion correlation engine previously derived `reports/ai_summary.json` from the audit database parent and wrote it as a hidden side effect of report construction. A database under a home-directory root therefore selected `~/reports/ai_summary.json`; a prior privileged run could leave that location unavailable to the normal GUI user. Intrusion Detection and Flight Recorder each rebuilt the same report, so one permission defect produced two failed refreshes.

The GUI remains an unprivileged, logged-in-user process. Generated GUI state is now stored below `~/Library/Application Support/MacAuditAgent/reports`. Privileged services must continue to use their own `/Library/Application Support` storage and an explicit IPC or copy boundary; they must not mutate this per-user file.

## Resolution and data flow

Report-directory resolution is:

1. Absolute, validated `MSAA_REPORT_DIR` development/test override.
2. Absolute, validated `MSAA_USER_DATA_DIR` configuration override plus `reports`.
3. `~/Library/Application Support/MacAuditAgent/reports`.

There is no persistent-report fallback to `/tmp`. Empty, relative, temporary, or obvious system-root overrides are rejected.

```text
scan/database snapshot
        |
        v
pure IntrusionCorrelationEngine.build_report()
        |
        v
IntrusionReportRefreshCoordinator (one snapshot per generation)
        |                         |
        |                         +--> secure atomic AI-summary persistence once
        v
Intrusion Detection + Flight Recorder render the same in-memory report
```

A write failure is represented by a stable `PersistenceResult`, logged once per generation, and shown as one concise GUI warning. It does not invalidate the in-memory analysis.

## Filesystem controls

The writer serializes before opening files, bounds legacy migration to 2 MiB, validates every existing path component with `lstat`, rejects links and special targets, verifies effective-user ownership, and confines the final target to its selected base. New directories are `0700`; generated JSON and lock files are `0600`.

Writes use an unpredictable `O_EXCL` temporary file in the destination directory, `O_NOFOLLOW` where available, complete writes, file `fsync`, atomic `os.replace`, mode verification, and best-effort directory `fsync`. A process lock plus `flock` serializes legitimate writers. Temporary files are removed on both success and failure. Errors do not include report content.

These controls address CWE-22, CWE-59, CWE-276, CWE-377, CWE-400, CWE-662, CWE-703, and CWE-732.

## Legacy migration

On the first report refresh, MSAA may copy `~/reports/ai_summary.json` to the resolved user report location. It imports only a bounded, readable, valid JSON regular file owned by the current user. It never follows a link, changes ownership, deletes the source, or makes failed migration fatal. Migration status and error code are attached to the report persistence metadata without recording contents.

## Diagnostics

Runtime doctor output includes `report_persistence`, with the resolved directory and target, link/ownership/writability state, current UID, safe probe result, and the last in-process persistence result. The probe creates and removes a random `0600` file; it never writes `ai_summary.json`.

## Bootstrap and fonts

`BOOTSTRAP_PARTIAL` is presented as a pending degraded state until a live Operational Health report completes. Its structured incomplete-capability reasons remain separate from report persistence. Report persistence needs no administrator bootstrap.

Theme application delegates proportional and fixed font selection to Qt's system font APIs. No production Python style requests the Windows-only `Segoe UI` family or hard-codes Apple's private system font name.

## Limitations and remediation

POSIX checks cannot repair an inherited deny ACL; the resulting structured not-writable/permission error remains visible. MSAA does not `chown` foreign-owned files. An operator should quit MSAA, inspect `~/Library/Application Support/MacAuditAgent/reports` with `ls -ldeO@`, and repair only that directory using an authorized administrator workflow. Running the GUI with `sudo` is not supported.

Cross-process locking uses advisory `flock`, so all legitimate writers must use this persistence helper. Atomic rename protects readers on the same filesystem; storage hardware and filesystem durability guarantees still apply after `fsync`.

## Verification

Automated coverage is in `tests/test_runtime_report_paths.py`, `tests/test_secure_report_io.py`, and `tests/test_intrusion_report_refresh.py`. It covers resolution, path security, atomic failure preservation, concurrency, migration, fail-soft shared GUI snapshots, diagnostic behavior, and font-source checks.
