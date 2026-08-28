# Resource Utilization Audit

## Summary

MSAA has several powerful subsystems that can become expensive if they run together: Apple Exposure/CVE refresh, rootkit checks, persistence scans, network inventory, report exports, alert overlay/notifier loops, daemon detector loops, and framework source validation. The stability refactor introduces shared resource budgets, scheduler primitives, API/cache controls, bounded subprocess execution, DB indexes, and a shutdown coordinator.

## Heavy Subsystem Inventory

| Subsystem | Module/File | Trigger | Startup | Refresh | Daemon | GUI | Network/API | Disk I/O | CPU/Memory Risk | Subprocesses | Timeout | Cancellation | Cache | Risk | Recommendation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---:|---:|---:|---|---|
| GUI startup | `mac_audit_agent/app.py`, `ui/main_window.py` | app launch | yes | no | no | yes | no | DB open | medium, Qt/AppKit | no | n/a | n/a | n/a | Python 3.14 GUI crash risk | block unsupported GUI Python before `QApplication`; lazy-load panels |
| Dashboard load | `ui/main_window.py` | app launch/page switch | yes | yes | no | yes | no | DB reads | medium if payloads large | no | partial | no | DB | may materialize latest scan | keep lightweight summaries and cache |
| Apple Exposure refresh | `cve_radar.py` | timer/manual | no cached first | yes | no | yes | Apple/NVD/CISA/EPSS | cache/DB writes | high | softwareupdate, defaults, xcodebuild | yes | partial | yes | API/command burst | use cache first, bounded requests, scheduler dedupe |
| NVD/CVE lookup | `vulnerability_review.py` | vulnerability review/Apple Exposure | no | yes | no | yes | NVD | cache | high large payload | no | yes | no | yes | large API page | cap records and timeout |
| CISA KEV lookup | `vulnerability_review.py` | catalog refresh | no | yes | no | yes | CISA | cache | medium | no | yes | no | yes | repeated fetch | cache TTL and circuit breaker |
| DoD/CMMC source refresh | `frameworks/source_registry.py` | framework audit | no | manual/fetch | no | CLI/pre-UAT | official HTTPS | cache | medium | no | yes | no | yes | source fetch during audit | cache first and label stale |
| Network Intelligence | `network_intelligence/*`, `network_discovery.py` | manual scan/audit | no | yes | optional | yes | optional LAN commands | DB/cache | high | route, ifconfig, lsof/nmap | mixed | partial | DB | external tool load | route through bounded subprocess runner |
| Persistence scan | `persistence_intelligence/*` | manual/audit | no | yes | yes controlled | yes | no | DB | medium/high | launchctl/plist reads | mixed | partial | DB | repeated full inventory | schedule with interval/jitter/backoff |
| Rootkit scan | `rootkit_detection/*` | manual/audit | no | yes | low frequency | yes | no | DB/report | high | kmutil, csrutil, systemextensionsctl | mixed | partial | DB | expensive system commands | schedule low frequency, bounded subprocess |
| Safe Scan | `collectors.py` | user/pre-UAT | no | manual | no | yes | no | DB/report | high | many system tools | mixed | partial | DB | all collectors at once | scheduler and output caps |
| Report exports | `reporting.py`, exporters | user | no | on demand | no | yes | no | heavy writes | high memory for large payloads | no | partial | no | source payload | stream/cap and release objects |
| Evidence package export | `apple_diagnostics/exporter.py`, evidence services | user | no | on demand | no | yes/CLI | no | zip writes | medium/high | maybe none | partial | no | no | large artifact package | manifest and stream content |
| Alert notifier loop | `user_notifier.py`, `monitor.py` user mode | LaunchAgent poll | no | loop | user notifier | no | no | DB poll | low if indexed | overlay process | yes | n/a | DB | polling full table | indexed pending queries and lightweight action queue |
| Daemon detector loop | `monitor.py` | daemon loop | no | loop | yes | no | no | DB writes | medium | detectors use tools | mixed | no | DB | bursts/duplicates | detector schedules with interval/jitter/backoff |
| UI timers | `ui/main_window.py`, panels | GUI | yes | loop | no | yes | no | DB reads | low/medium | no | n/a | stop on quit | DB | timers survive quit | shutdown coordinator stops timers |
| Tray/menu shutdown | `ui/main_window.py`, `ui/app_shutdown.py` | tray/Dock/Cmd+Q | no | no | no | yes | no | DB close | medium | no | n/a | yes | n/a | orphan workers/DB | unified `AppShutdownCoordinator` |
| SQLite access | `storage.py` | all modes | yes | yes | yes | yes | no | DB | lock/full-scan risk | no | busy_timeout | n/a | WAL | slow queries | add indexes and paginated access |

## Startup-Heavy Work Identified

- `MainWindow` builds many panels and starts `cve_radar_timer`.
- Latest scan payload and cached Apple Exposure state may be loaded at startup.
- DB schema setup is broad but acceptable if indexed and WAL-backed.
- GUI startup must be blocked on unsupported Python GUI runtimes before `QApplication`.

## Duplicate Work Risk

- GUI Apple Exposure refresh and pre-UAT scan audit can both refresh catalog data.
- Daemon and user notifier can both touch alert traces/state if not separated.
- Rootkit/persistence/network checks can run in full Pre-UAT together.

## API/Network-Heavy Workflows

- NVD CVE API, CISA KEV, FIRST EPSS, Apple security releases.
- Framework source validation if `fetch=True`.
- Optional network discovery scans when enabled.

## Recommendations Implemented

- `performance/resource_budget.py`: Low Resource, Balanced, Thorough budgets.
- `performance/work_scheduler.py`: bounded scheduler with dedupe/cancel.
- `performance/api_refresh_manager.py`: cache-first refresh, rate limiting, circuit breaker.
- `cache/cache_manager.py`: atomic JSON cache, corrupt cache detection.
- `performance/subprocess_runner.py`: timeout/output-capped subprocess wrapper.
- `performance/db_optimization.py`: indexes for event, alert trace, and finding queries.
- `runtime/platform_profile.py`: Intel/Apple Silicon/Rosetta/tool/Python profile.
- `ui/app_shutdown.py`: shared shutdown coordinator for tray/Dock/menu paths.
