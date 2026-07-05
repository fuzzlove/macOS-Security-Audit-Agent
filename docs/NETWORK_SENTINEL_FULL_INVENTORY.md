# Network Sentinel Full Inventory

Source root: `macOS-Network-Sentinel`

Integration target: native MSAA feature `Network Intelligence (powered by Network Sentinel)`.

Integration rule: Sentinel code is source material only. MSAA must not run the old Sentinel GUI, CLI, standalone database, or scanner loop as a subprocess. Reused logic is normalized through `mac_audit_agent/network_intelligence/`, MSAA SQLite storage, MSAA alert events, MSAA reports, and the new MSAA UI tab.

## Entrypoints

| File | Purpose | Integration decision |
| --- | --- | --- |
| `macOS-Network-Sentinel/network_sentinel/__main__.py` | Standalone package entrypoint. | Discard as runtime entrypoint; MSAA owns launch/UI. |
| `macOS-Network-Sentinel/network_sentinel/app.py` | Standalone app bootstrap. | Discard; replaced by MSAA `MainWindow` tab integration. |
| `macOS-Network-Sentinel/network_sentinel/cli.py` | Standalone CLI scanning/report actions. | Do not reuse as CLI; collector behavior is adapted natively. |
| `macOS-Network-Sentinel/network_sentinel/__init__.py` | Package metadata. | Discard. |

## Collectors

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/collectors/network_connections.py` | `lsof` active TCP/UDP connection collection and parsing. | Merged into `network_intelligence/connection_parser.py`, `connections.py`, and `collector.py`. |
| `network_sentinel/collectors/listening_ports.py` | `lsof` listening port collection, process owner, service guess. | Merged into `network_intelligence/connection_parser.py`, `port_scanner.py`, and `ports.py`. |
| `network_sentinel/collectors/routes.py` | Route/gateway collection. | Adapted in `network_intelligence/dns_gateway.py`. |
| `network_sentinel/collectors/interfaces.py` | Interface/IP collection. | Adapted in `network_intelligence/dns_gateway.py` and `posture.py`. |
| `network_sentinel/collectors/wifi.py` | Wi-Fi state helper. | Future: MSAA can add SSID only where privacy policy allows. |
| `network_sentinel/collectors/dns_cache.py` | DNS cache/state collection. | Partially replaced by `scutil --dns` parsing in `dns_gateway.py`. |
| `network_sentinel/collectors/processes.py` | Process metadata helpers. | Replaced by MSAA normalized process fields from `lsof`; deeper metadata remains future work. |
| `network_sentinel/collectors/process_metadata.py` | Signing/hash/process enrichment. | Future: integrate with MSAA integrity/signing systems instead of duplicating. |
| `network_sentinel/collectors/firewall.py` | Firewall state collection. | Future: MSAA has separate security assessment areas; not duplicated in Network Intelligence. |
| `network_sentinel/collectors/packet_capture.py` | Packet capture wrapper. | Not imported by default; MSAA keeps packet capture separate and explicitly authorized. |
| `network_sentinel/collectors/__init__.py` | Collector package export. | Discard. |

## Detection, Baselines, and Scoring

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/detection/rules.py` | Network finding rules for connections, listeners, DNS, drift. | Merged into `network_intelligence/risk_scoring.py`. |
| `network_sentinel/detection/scoring.py` | Scoring helpers. | Merged into `network_intelligence/risk_engine.py` and `risk_scoring.py`. |
| `network_sentinel/detection/baselines.py` | Baseline compare helpers. | Merged into `network_intelligence/baseline.py`. |
| `network_sentinel/detection/allowlist.py` | Allowlist rules. | Future: map into MSAA settings/policy; not kept as separate allowlist. |
| `network_sentinel/detection/settings.py` | Sentinel-specific settings. | Replaced by MSAA monitor settings. |
| `network_sentinel/detection/reputation.py` | Reputation hooks. | Future optional enrichment; no external lookups by default. |

## Storage and Models

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/storage/models.py` | Sentinel dataclasses for connections, listeners, findings, scan results. | Normalized into `network_intelligence/models.py`. |
| `network_sentinel/storage/database.py` | Standalone Sentinel SQLite database. | Discard as DB; MSAA storage owns `network_connections`, `network_ports`, `network_posture`, `network_findings`, `network_baseline`, `network_events`, and diagnostics tables. |
| `network_sentinel/storage/__init__.py` | Storage package export. | Discard. |

## UI

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/gui/main_window.py` | Standalone Sentinel window. | Discard; replaced by MSAA `NetworkIntelligencePanel`. |
| `network_sentinel/gui/dashboard.py` | Dashboard widgets. | Concepts merged into Network Intelligence overview. |
| `network_sentinel/gui/connections_table.py` | Connections table. | Recreated in MSAA UI with normalized columns. |
| `network_sentinel/gui/listeners_table.py` | Listener table. | Recreated in MSAA UI with visibility/risk columns. |
| `network_sentinel/gui/alerts_panel.py` | Sentinel alert display. | Replaced by MSAA alert pipeline and notifier. |
| `network_sentinel/gui/history_panel.py` | Sentinel history display. | Replaced by MSAA timeline/storage. |
| `network_sentinel/gui/process_panel.py` | Process details display. | Future: use MSAA evidence/context dialogs. |
| `network_sentinel/gui/settings_panel.py` | Sentinel settings panel. | Replaced by MSAA monitor settings. |
| `network_sentinel/gui/packet_capture_panel.py` | Capture controls. | Not merged into Network Intelligence default view; MSAA packet capture remains explicit. |
| `network_sentinel/gui/scan_worker.py` | Background scan worker. | Replaced by MSAA collector invocation. |
| `network_sentinel/gui/app_icon.py`, `network_sentinel/gui/__init__.py` | UI support. | Discard. |

## Reporting

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/reporting/export_json.py` | Sentinel JSON export. | Replaced by MSAA report payloads and `network_intelligence/report.py`. |
| `network_sentinel/reporting/export_html.py` | Sentinel HTML report. | Replaced by MSAA report sections. |
| `network_sentinel/reporting/export_csv.py` | CSV export. | Future if MSAA export UI needs CSV. |
| `network_sentinel/reporting/export_bundle.py` | Bundle export. | Replaced by MSAA evidence snapshots. |
| `network_sentinel/reporting/export_comparison.py` | Baseline comparison export. | Merged conceptually into Network Intelligence drift report data. |
| `network_sentinel/reporting/__init__.py` | Reporting package export. | Discard. |

## Utilities

| File | Purpose | Integration decision |
| --- | --- | --- |
| `network_sentinel/utils/command.py` | Command runner wrappers. | Replaced by scoped MSAA collector runner. |
| `network_sentinel/utils/macos.py` | macOS helper routines. | Adapted where needed in collectors. |
| `network_sentinel/utils/timestamps.py` | Timestamp helpers. | Replaced by MSAA `utc_now_iso`. |
| `network_sentinel/utils/hashing.py` | Hash helper. | Future: use MSAA integrity helpers. |
| `network_sentinel/utils/resources.py` | Resource lookup. | Discard. |

## Tests and Assets

| File | Purpose | Integration decision |
| --- | --- | --- |
| `macOS-Network-Sentinel/tests/test_detection_and_reporting.py` | Sentinel detection/report tests. | Replaced by MSAA Network Intelligence tests. |
| `macOS-Network-Sentinel/tests/test_gui_tables.py` | Sentinel GUI table tests. | Replaced by MSAA UI panel tests. |
| `macOS-Network-Sentinel/resources/icon/*`, `assets/icon_placeholder.png` | Standalone app icons. | Discard; MSAA branding remains source of truth. |
| `macOS-Network-Sentinel/reports/.gitkeep` | Standalone report output folder. | Discard; MSAA report directories remain source of truth. |
| `macOS-Network-Sentinel/README.md` | Sentinel documentation. | Used for discovery only. |
| `macOS-Network-Sentinel/pyproject.toml`, `requirements.txt` | Standalone dependencies. | Reviewed for conflicts; MSAA dependencies remain authoritative. |

## Dependency Notes

No license file was found under `macOS-Network-Sentinel`. Keep attribution in MSAA docs until provenance is clarified.

Sentinel's PySide6 GUI dependency overlaps with MSAA's Qt UI stack, but the standalone GUI is not imported. Optional packet capture and external reputation concepts are not enabled by default because MSAA safety policy requires read-only local collection unless the user explicitly authorizes active probing.

## Required Refactors Completed

- Normalized Sentinel connection, listener, posture, and finding data into MSAA dataclasses.
- Added native read-only collectors under `mac_audit_agent/network_intelligence/`.
- Added MSAA SQLite tables for snapshots, connections, ports, posture, findings, baseline, events, and diagnostics.
- Added a native MSAA `Network Intelligence` tab.
- Added conversion of network findings into MSAA background monitor events so the existing alert/timeline path can consume them.
- Added diagnostics that expose collector, DB, alert pipeline, UI, settings, and permissions status.

## Required Refactors Still Tracked

- Deeper process signing enrichment should be unified with MSAA integrity systems.
- Optional reputation lookups should remain disabled unless MSAA adds explicit privacy controls.
- Packet capture stays outside the default Network Intelligence flow and must remain explicitly authorized.
