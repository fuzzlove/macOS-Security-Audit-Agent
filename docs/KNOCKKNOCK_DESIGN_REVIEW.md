# KnockKnock Autorun Review and MSAA Translation

## Scope and licensing boundary

The locally supplied KnockKnock repository was reviewed as a reference catalog of macOS autorun and loadable-plugin mechanisms. The project is GPL-3.0, and its signing implementation also carries a separate Creative Commons Attribution-NonCommercial notice. MSAA declares MIT licensing. No KnockKnock source, plugin implementation, whitelist, UI asset, private-framework call, or parser was copied. The changes described here independently implement general autorun discovery concepts using Python standard-library facilities and documented filesystem formats.

The review covered every scanner plugin, shared application/launch-item enumeration, result models, hashing and code-signing classification, trusted-item filters, scan cancellation, JSON output, saved-scan comparison, VirusTotal behavior, and UI presentation.

## Plugin-by-plugin coverage review

| KnockKnock category | MSAA before review | Decision |
| --- | --- | --- |
| Launch Items | LaunchAgent/LaunchDaemon parsing, baselines, risk and daemon change monitoring. | Existing MSAA coverage retained. |
| Background Task Management | BTM directory inventory and daemon artifact lifecycle; no private BTM parser. | Retain supported fallback and native-event roadmap. |
| Login Items | Current-user login item query plus background-item inventory. | Add embedded application login-helper discovery. |
| Cron Jobs / Periodic Scripts | Cron, `at`, periodic directories and script inventory. | Existing coverage retained. |
| Shell Configs | User and system zsh/bash/profile files with privacy-preserving suspicious-line extraction. | Existing coverage retained. |
| Authorization Plugins | SecurityAgent plugin directories. | Existing coverage retained. |
| Directory Services Plugins | Missing. | Added `.dsplug` inventory. |
| Login/Logout Hooks | Missing. | Added structured parsing of system and user loginwindow plists. |
| Event Rules | Missing. | Added bounded `emond` rule parsing, including configured additional absolute rule paths. |
| Startup Scripts | Partially represented by broad scheduled/script scanning. | Added explicit legacy startup-file detection. |
| Library Inserts | Missing explicit `DYLD_INSERT_LIBRARIES` analysis. | Added launchd `EnvironmentVariables` and application `LSEnvironment` parsing, including colon-separated libraries. |
| Dylib Proxies | Missing; reliable identification requires Mach-O dependency inspection. | Deferred to native Mach-O sensor work; no `lsof /` full-system scan adopted. |
| Kernel/System Extensions | Extension inventory already present. | Existing coverage retained. |
| Finder and application extensions | Browser/system extension inventory existed, but not every registered `pluginkit` class. | Deferred to a documented-command capability because output formats and per-user registration vary by macOS release. |
| Dock Tile Plugins | Missing. | Added `NSDockTilePlugIn` discovery from application Info.plists. |
| Quick Look Plugins | Missing. | Added supported filesystem inventory of user and system `.qlgenerator` bundles; private Quick Look APIs were not adopted. |
| Spotlight Importers | Missing. | Added user and system `.mdimporter` inventory. |
| Browser Extensions | Chrome-family, Firefox and Safari filesystem coverage plus native messaging hosts. | Existing broader privacy-aware coverage retained. |

## Architecture comparison

KnockKnock is a point-in-time enumerator organized as independent plugins. It shares expensive application and launch-item enumeration between plugins, resolves bundle executables, hashes files, extracts signing and notarization information, optionally queries VirusTotal, filters known/Apple items, serializes results, and compares saved scans by stable item identity and selected trust fields.

MSAA already provides stronger operational layers around this inventory: named baselines, added/removed/modified/hash/permission/owner/signature/load-state comparisons, risk and trust scores, MITRE mappings, coverage degradation, evidence persistence, daemon monitoring, alert correlation, and incident workflow. The useful KnockKnock lesson was therefore mechanism completeness rather than adopting its UI or scan engine.

## Implemented changes

1. Added a `LegacyAutorunScanner` for login/logout hooks, `emond` event rules, legacy startup scripts, Directory Services plugins, Spotlight importers, and Quick Look generators.
2. Added a `DynamicLoaderPersistenceScanner` for `DYLD_INSERT_LIBRARIES` and `__XPC_DYLD_INSERT_LIBRARIES` in launchd and application property lists. Colon-separated declarations become separate attributable items.
3. Added an `ApplicationAutorunPluginScanner` for Dock tile plugins and embedded `Contents/Library/LoginItems` helpers.
4. Registered the scanners in the default persistence engine, so coverage, findings, reports, baselines, and UI inventory receive them automatically.
5. Added MITRE mappings for every new mechanism and explicit inherent-risk weights. Dynamic-library insertion is high risk even when the library is outside a temporary directory.
6. Fixed an existing target-state bug where a persistence item without an executable target could accidentally treat the current working directory as its target.
7. Extended bounded daemon snapshots to watch loginwindow configuration, `emond` rules, legacy startup files, Directory Services plugins, Spotlight importers, and Quick Look generators for additions, modifications, and removals.
8. Kept enumeration bounded: application roots, rule files, plugins, helpers, and daemon artifacts all have explicit caps.

## Safety and reliability improvements over the reference patterns

- MSAA uses structured plist parsing and never executes an extracted autorun command.
- Additional `emond` rule paths must be absolute and are mapped through the scanner's testable system root.
- Missing, malformed, or unreadable sources produce partial-coverage warnings rather than terminating the complete scan.
- MSAA does not use private Quick Look functions, which are fragile across macOS releases.
- MSAA does not run a full-root `lsof` operation to infer dylib proxies. That approach is expensive, privacy-sensitive, and only observes currently loaded processes.
- MSAA does not upload hashes or files. Reputation enrichment remains optional and explicit.
- Apple signing or a static whitelist is not treated as permanent authorization. Trust is advisory and baseline changes remain visible.
- Saved-scan comparison remains MSAA's richer field-level baseline model rather than a display-only textual diff.

## Remaining roadmap

Native Mach-O inspection could safely close the dylib-proxy gap by parsing load commands offline and detecting libraries whose install names intentionally collide with dependencies while residing earlier in loader search paths. It should be bounded to autorun targets, avoid loading examined binaries, support universal binaries, and record architecture-specific evidence.

A future signed macOS helper may enrich new inventory items using Security.framework with current static-code validity, designated requirement, signing identifier, team identifier, hardened-runtime flags, notarization assessment, and package receipt. Results must be cached by file identity and content hash to avoid running expensive checks on every scan. Signature status must inform risk without suppressing change detection.

Registration-aware extension enumeration should use documented `pluginkit` commands through MSAA's controlled command runner, retain raw-command provenance, enforce timeouts, and degrade cleanly when output formats or permissions differ.
