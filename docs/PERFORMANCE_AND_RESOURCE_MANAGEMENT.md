# Performance and Resource Management

MSAA defaults to the Balanced resource profile. Heavy work is expected to be scheduled, bounded, cache-aware, and cancellable where safe.

## Resource Profiles

- Low Resource: one task/subprocess, API limit 10/min, short API timeout, heavy refresh user-triggered.
- Balanced: default, two tasks/subprocesses, API limit 30/min, cache-first background refresh.
- Thorough: analyst mode, three tasks/subprocesses, API limit 60/min, still bounded.

Profiles are stored in the active MSAA DB under `performance.resource_profile`.

## Diagnostics

Operational diagnostics can read:

- process memory from `performance.memory.get_process_memory_mb()`
- scheduler snapshot from `WorkScheduler.snapshot()`
- cache size and largest files from `CacheManager.diagnostics()`
- platform/tool profile from `detect_platform_profile()`

## Rules

- Heavy scans do not run unbounded.
- API refreshes use cache and timeout.
- Subprocess output is capped.
- Unsupported GUI Python runtimes are blocked before Qt/AppKit startup.
