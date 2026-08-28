# Packet Capture Incident-Response Readiness

MSAA provides a guided, explicit packet-capture workflow under **Advanced Evidence → Packet Capture Snapshot**. Capture never starts automatically.

The readiness screen verifies the built-in `/usr/sbin/tcpdump` collector, available interfaces, `/dev/bpf` access, the evidence directory, and free disk space. It also requires the analyst to acknowledge authorization and privacy obligations before capture options become available.

## Prepare before an incident

1. Record the case or incident identifier, written authorization, collection scope, retention period, and approved evidence custodians.
2. Verify `/usr/sbin/tcpdump` exists. macOS normally includes it; no Python capture package is required.
3. Configure packet-device access. Prefer Wireshark's signed ChmodBPF component for a managed analyst workstation, then sign out and back in. Confirm this approach with the organization's endpoint and least-privilege policy.
4. Do not run the MSAA graphical application as root. MSAA never requests or stores an administrator password. Where persistent BPF access is prohibited, use the exact generated `sudo tcpdump` command in Terminal as a separately authorized manual collection.
5. Select a protected evidence location with sufficient free space. Treat PCAP files as potentially containing credentials, content, personal data, and regulated information.
6. Reopen the readiness screen and use **Recheck Readiness**.

## Capture choices

- Use the narrowest interface and BPF expression that preserves relevant evidence. Custom BPF supports combinations such as `host 192.0.2.4 and tcp port 443`.
- The recommended 96-byte snapshot preserves headers and timing with less payload exposure.
- Full-packet capture uses snapshot length zero and should be selected only when payload preservation is expressly authorized.
- Interactive captures are bounded to ten minutes and stop automatically. The analyst can stop earlier at any time.

## Evidence preservation

MSAA writes the PCAP, a JSON collection record, and SHA-256 sidecars for both files. The record contains the PCAP SHA-256, byte count, interface, filter, snapshot length, start/end times, collector host and effective UID, command arguments, exit status, and bounded error text. Live packet contents are not embedded in MSAA reports.

After capture, preserve the original files read-only according to organizational chain-of-custody procedures. Analyze a verified working copy, record every transfer, and do not upload captures to third-party services without separate approval.
