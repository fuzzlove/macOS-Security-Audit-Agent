# Network Sentinel Integration Review

Source directory: `macOS-Network-Sentinel`

Native MSAA subsystem: `mac_audit_agent/network_intelligence`

UI surface: `Network Intelligence`

## Source Summary

Network Sentinel contains a standalone PySide app, CLI, SQLite storage layer, collectors, detection rules, baseline comparison, report exporters, and GUI panels. Its useful collector and detection behavior has been extracted into native MSAA modules. Its independent runtime surfaces are intentionally not used.

## Reused or Adapted

- `lsof` active connection parsing.
- `lsof` listener parsing and service guesses.
- Route/gateway posture collection.
- DNS server posture collection.
- VPN/proxy posture checks.
- Baseline comparison concepts for new connections, listeners, DNS, gateway, VPN, and proxy changes.
- Risk rules for new listeners, all-interface exposure, unknown owners, suspicious paths, DNS/gateway drift, VPN drift, proxy drift, and visibility mismatches.
- Finding structure with evidence, suggested fixes, MITRE mappings, and NIST mappings.

## Not Imported

- Standalone app entrypoints: MSAA owns application lifecycle.
- Standalone CLI: MSAA must not shell out to Sentinel.
- Standalone Sentinel database: MSAA SQLite is the single source of truth.
- Standalone GUI panels: MSAA has one Network Intelligence tab.
- Standalone report exporters: MSAA reporting and evidence snapshots own exports.
- Packet capture default UI: MSAA keeps capture explicitly authorized and separate from read-only Network Intelligence.
- External reputation hooks: disabled until MSAA has explicit privacy controls.

## Native Flow

Network Intelligence collector -> normalized MSAA models -> MSAA SQLite storage -> MSAA background monitor events -> alert policy/notifier path -> security timeline -> reports and evidence snapshots.

## Storage Format

MSAA stores network data in:

- `network_intelligence_snapshots`
- `network_connections`
- `network_ports`
- `network_posture`
- `network_findings`
- `network_baseline`
- `network_events`
- `network_sentinel_diagnostics`

The old Sentinel database is not used.

## Alerting Logic

Network findings are converted to `BackgroundMonitorEvent` records with canonical event types including:

- `new_network_connection`
- `new_listening_port`
- `dns_changed`
- `gateway_changed`
- `vpn_changed`
- `proxy_changed`
- `network_visibility_mismatch`

The existing MSAA notifier and bottom-right alert system remain responsible for visible delivery.

## License and Attribution

No license file was found in the copied Sentinel directory. Keep this review and the full inventory as attribution/provenance notes until the upstream license is known.
