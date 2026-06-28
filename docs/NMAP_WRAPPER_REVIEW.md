# Nmap Wrapper Review

## Current Scanner Files and Functions

- `mac_audit_agent/collectors.py`
  - `CollectorSuite._collect_localhost_port_scan()`
  - `CollectorSuite.collect_full_localhost_port_scan()`
  - `CollectorSuite._scan_localhost_port_tcp()`
  - `CollectorSuite._scan_localhost_port_udp()`
  - `CollectorSuite._grab_localhost_tcp_banner()`
  - `CollectorSuite._findings_for_localhost_scan()`
- `mac_audit_agent/analyzers.py`
  - `parse_lsof_listening_output()`
  - `parse_lsof_udp_output()`
  - `parse_netstat_tcp_output()`
- `mac_audit_agent/ui/main_window.py`
  - `run_scan()`
  - `run_full_localhost_port_scan()`
  - `_populate_scan_results()`
- `mac_audit_agent/reporting.py`
  - `export_scan_result_json()`
  - `export_scan_result_html()`
- `mac_audit_agent/storage.py`
  - `record_scan_result()`
  - `record_snapshots()`
  - `write_scan_logs()`

## Existing TCP Scan Method

The internal fallback scanner opens TCP connections to `127.0.0.1` with `socket.create_connection()`. Safe scans use a short curated port list, verbose scans use configured concerning ports, and aggressive scans scan `1-65535`.

## Existing UDP Scan Method

The internal fallback scanner creates a UDP socket, connects it to `127.0.0.1`, sends an empty datagram, and treats a timeout as responsive or unknown. `ConnectionRefusedError` is treated as closed.

## Current Limitations

- TCP service detection is limited to connect success and optional passive banner reads.
- UDP detection is ambiguous because UDP silence can mean open, filtered, or no application response.
- The internal scanner does not identify service names, product strings, versions, or Nmap-style reasons.
- Full scans are slow because they run from Python in-process.
- UDP scans can over-report responsive or unknown ports.
- Safe scans can miss ports outside the curated list.

## Performance Issues

- Aggressive full-port scans iterate through 65,535 TCP ports and 65,535 UDP ports in Python.
- UDP timeouts accumulate quickly.
- Full scans run as a long UI action and can take substantial time even though they are local-only.

## False Positives and False Negatives

- False positives: UDP timeout handling can label ports as responsive or unknown when no service is confirmed.
- False positives: process enumeration can miss ownership because of permissions, transient listeners, or parser gaps.
- False negatives: safe scans only check selected ports.
- False negatives: TCP listeners that start after process enumeration can be missed by `lsof`/`netstat`.
- False negatives: services bound only to IPv6 loopback may not be reached by an IPv4-only `127.0.0.1` probe.

## Where Results Are Displayed

- Main results tabs:
  - `Localhost Port Scan`
  - `Full Localhost Port Scan`
  - `Ports`
- New Nmap wrapper UI:
  - `Nmap Local Scan`

## Where Results Are Stored

- Full scan payload: `scan_results.payload_json`
- Port ownership snapshots: `port_snapshots`
- Raw JSONL logs under the scan log directory
- New Nmap tables:
  - `nmap_scans`
  - `nmap_scan_ports`

## Where Results Are Exported

- JSON reports via `export_scan_result_json()`
- HTML reports via `export_scan_result_html()`
- JSONL scan logs via `write_scan_logs()`
- New Nmap UI export writes the Nmap result payload as JSON.

## Replacement Strategy

MSAA now prefers Nmap when available for enhanced localhost TCP/UDP scanning and keeps the internal socket scanner as fallback. The default profile remains `Localhost TCP Quick` against `127.0.0.1`. UDP and full scans require explicit UI confirmation and warn about runtime and privilege requirements.
