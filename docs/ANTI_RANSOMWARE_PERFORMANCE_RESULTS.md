# Anti-Ransomware Performance Results

## Bounded lifecycle characterization — 2026-07-10

Command: `python3.14 -m benchmarks.anti_ransomware.lifecycle_soak --seconds 5 --output /tmp/msaa-ar-soak.json`

- Workload: explicit temporary-root degraded metadata observer.
- Duration: 5.001 seconds.
- Synthetic writes: 398.
- Events delivered: 396.
- Dropped events: 0.
- Scan overflow: false.
- Threads: 1 before, 1 after.
- File descriptors: 4 before, 4 after.
- Shutdown: complete in 0.000096 seconds.
- Raw `ru_maxrss`: 20,086,784 on this macOS arm64 host.

This is `CHARACTERIZATION_ONLY_UNAPPROVED_BUDGET`. It is not an Endpoint Security callback/AUTH measurement, not a long-duration soak, and not performance qualification.

Run `python3.14 benchmarks/anti_ransomware/python_benchmark.py` for build-bound JSON. Native callback latency, AUTH margin, battery, Apple Silicon 8 GB soak, higher-memory, and Intel results remain `NOT_VERIFIED`. AR-GAP-010 cannot close until budgets are approved before qualification.
