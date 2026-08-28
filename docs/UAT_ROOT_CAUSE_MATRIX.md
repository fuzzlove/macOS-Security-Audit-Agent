# Pre-UAT Root-Cause Matrix

Baseline: `pre-uat-a0116a200e06` (`PASS=90`, `BLOCKER=14`, `FAIL=5`, `DEGRADED=4`, `NOT_VERIFIED=4`, `SKIPPED=7`, `HARNESS_ERROR=0`).

| Root cause | Affected checks | Classification |
|---|---|---|
| System mode deployment incomplete | `daemon.system_launch_daemon`, `daemon.heartbeat`, runtime and readiness gates | BLOCKER/FAIL |
| Conflicting obsolete user monitor | `daemon.user_launch_agent`; now represented separately as `daemon.conflicting_monitor_deployment` | FAIL/BLOCKER |
| Notifier input source and installed arguments misaligned | `daemon.notifier_heartbeat`, settings notifier deliverability, `alert.delivery_trace` | BLOCKER |
| Diagnostic event suppressed or not received | `alert.delivery_trace`; visible rendering remains separate | BLOCKER |
| Protected source differs from signed manifest | `integrity.source_files_match_manifest`, aggregate preflight | BLOCKER |
| Integrity predicate cascade | policy, manifest, signer, path, generated-artifact, and headless checks in the baseline | inaccurate cascading BLOCKER/FAIL, corrected to predicate-local results |
| Parent-process GUI contamination | `integrity.preflight_passed`, `integrity.integrity_cli_headless_safe` | inaccurate cascading BLOCKER, evaluated in an isolated subprocess |
| Independent verifier result semantics | `integrity.independent_verify_matches` | inaccurate BLOCKER when both verifiers agreed on source mismatch |
| Missing Office extras | `exports.word`, `exports.excel`, `frameworks.cmmc_word`, `frameworks.cmmc_excel` | DEGRADED; two distributions, four capability checks |
| Required interactive evidence unavailable in headless execution | menu shutdown, button overlap, cropping, responsive rows, bottom-right visibility | NOT_VERIFIED/SKIPPED |
| No current scan requested | saved/current Safe Scan and dependent scan evidence | SKIPPED |
| Missing current packaging/release evidence | clean installs, supported-Python matrix, PyInstaller, size/startup/RSS | release gate incomplete |
| Oversized repeated evidence | integrity preflight, scope, hygiene, launchctl/log payloads | report-quality defect |

Statuses remain tied to their check-specific acceptance predicates. The source mismatch and live deployment defects are not converted to PASS by this grouping.
