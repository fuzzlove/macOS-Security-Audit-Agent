# Anti-Ransomware Source Review

Originally retrieved 2026-07-10 from the official Objective-See repository.
The review was refreshed 2026-08-26 against commit
`516918e334d1b84b9f7ddf604f91ae330e2eb444` (2026-08-05). The repository
reports GPL-3.0. The upstream checkout is stored only in the ignored
`.research-cache/RansomWhere` research directory and is not packaged, imported,
linked, invoked, or distributed as an MSAA component.

Reviewed `README.md`, `LICENSE.md`, `Daemon/Monitor.m`, `fileChecks.[mh]`, `Process.[mh]`, `Event.[mh]`, `Events.[mh]`, `Rules.[mh]`, `XPCDaemon.m`, entitlements, Application, Installer, Shared, and Testing trees. Key SHA-256 values:

| File | SHA-256 |
|---|---|
| README.md | `d5e179074a4cef22088556840a59f65e5f8ad058cf4c9d6b3fc7c74b9ad4a0cd` |
| LICENSE.md | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| Daemon/Monitor.m | `512031b0c0eb7ee3150ff2323d0136159dc79ff2b861fbebe3d28f380add477c` |
| Daemon/fileChecks.m | `000d77fffcf3855a324774832ce532d53952d3900ace6a4fbe288c3e84cc7cab` |
| Daemon/Process.m | `853cddd7c5ce0932460afa64f2627235c124f5d9cbe40a034d765b4326298c67` |
| Daemon/Rules.m | `39bbb660548a312aa784483efacc6b336356d99f557f6f46321c7a6eb498f889` |

Current code subscribes to Endpoint Security notify exec, exit, close, and rename; attributes file events to process records; evaluates eligible files using entropy/randomness statistics; retains five qualifying paths within thirty seconds; suspends with `SIGSTOP`; and sends an alert supporting allow/block and remembered decisions. Platform binaries are normally excluded except recognized interpreter cases. Optional notarization/App Store preference can bypass monitoring.

Important current limitations include fixed size exclusions, header/content exclusions, threshold evasion, incomplete pre-start ancestry, and user-decision dependence. The current source also contains cache-eviction logic that resumes a suspended process to avoid orphaning it; MSAA intentionally treats containment ownership independently so notification/cache failure cannot silently resume a suspect.

No Objective-See implementation code, comments, identifiers, UI assets, or test code was incorporated. MSAA's Python algorithms and tests were written independently from observable behavioral requirements. RansomWhere is cited as prior art, not presented as an MSAA port.

## Independent MSAA improvements

MSAA's `adaptive_detector.py` is a separate metadata contract and algorithm. It
adds process-tree correlation; distinct-file rather than raw-event thresholds;
rename, deletion, directory, volume, and write-volume fanout; local rate-baseline
deviation; first-seen and interpreter context; duplicate-event rejection;
bounded LRU state; coverage-aware response gating; and stable reason codes.

Signing status is supporting context only. Unsigned status alone scores zero,
and validly signed or notarized software is still evaluated when its behavior is
dangerous. Automatic response eligibility requires at least two destructive
behavior families, complete telemetry, and the normal MSAA containment policy.
The detector never performs containment itself.
