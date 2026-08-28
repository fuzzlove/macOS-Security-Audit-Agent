# Ingress Network Segmentation

MSAA now contains the safety-critical controller foundation for two-ended segmentation validation. It does not certify PCI DSS, NIST, CISA, DoD, Zero Trust, or FIPS compliance. Qualified personnel may use preserved technical evidence as one input to an assessment.

## Implemented

- Flat navigation entry **Ingress > Network Segmentation**, sharing the existing Network Segmentation page and primary MSAA database.
- Versioned migration creating engagement, authorization, zone, asset, probe, capability, flow, plan, case, attempt, sender/receiver observation, inference, finding, artifact, remediation, retest, compliance mapping, and audit-event tables with foreign keys.
- Engagement and expected-flow models with IPv4/IPv6, TCP/UDP/ICMP/ICMPv6/SCTP/IP protocol representation.
- Programmatic CIDR, exclusion, address-family, protocol, port, special-address, test-window, and DNS-change enforcement.
- Deterministic two-ended classification. Destination observation or a destination-generated RST/ICMP rejection proves path reachability; a closed service is never treated as segmentation.
- Unhealthy, absent, overflowing, or wrong-interface observer evidence produces `INDETERMINATE`.
- Append-only SHA-256 audit chaining with verification.
- Size-bounded authenticated offline job/result bundle primitives. The current HMAC adapter is an internal implementation seam, not the final engagement-certificate transport.
- Native bounded TCP-connect and UDP nonce backends with cancellation primitives and no shell execution.
- Safe Nmap discovery from fixed paths, executable hashing, validated argument lists, `shell=False`, bounded output, and XML rejection for DTD/entity declarations.
- Prominent limited-vantage statement that cannot be hidden by the current UI.

## Nmap ingress profiles

The **Network Segmentation** page has separate **Egress Tests** and **Ingress Tests** tabs. Ingress exposes fixed profiles rather than arbitrary arguments: Safe TCP Common, TCP Top 100, TCP Top 1000, Full TCP 1–65535, Safe UDP Common, UDP Top 50, DNS TCP/UDP 53 path validation, ICMP, ICMPv6, and selected IP protocols. Targets must be contained by the entered authorized CIDR and are capped at 4,096 addresses. Full TCP requires a second high-traffic confirmation.

Nmap is discovered only at trusted fixed paths, hashed, invoked with `shell=False`, and asked for XML. DTD/entity input is rejected. Raw XML is retained in the JSON evidence export as Base64 plus its SHA-256 hash. A closed TCP service is reported as inferred network reachability; filtered and open|filtered states without receiver evidence are indeterminate.

These profiles test reachability of protocols commonly relevant to ingress, egress, management, and potential exfiltration paths. They do not transmit stolen data, DNS tunnels, deceptive payloads, evasion traffic, exploits, credentials, or protocol abuse.

## Not yet operational

The destination probe service, passive BPF observer, leased synthetic responder, mTLS enrollment/management transport, signed engagement-certificate implementation, air-gap import/export UI, full wizard editor, live two-ended matrix, emergency-stop orchestration, PCAP acquisition, compliance reports, baseline comparison, artifact staleness, and probe installers are not complete. Their buttons remain disabled or explain the limitation. The Nmap ingress tab is operational when Nmap is installed, but its scanner-only conclusions remain inferred or indeterminate. MSAA does not simulate successful enrollment, capture, or two-ended validation.

The existing outbound provider tester remains available below the ingress controller status. It is not destination-observer-backed ingress evidence.

## Threat boundaries

The management plane must never relay test traffic or provide shell, file-transfer, proxy, tunneling, forwarding, dynamic-code, or credential functionality. All test traffic must follow the assessed path. Privileged capture/raw operations must use the existing authenticated MSAA helper; the GUI must not invoke `sudo` or run as root.

## Tests

```sh
.venv/bin/python -m pytest -q \
  tests/test_ingress_segmentation_core.py \
  tests/test_network_segmentation_layout.py \
  tests/test_network_segmentation.py \
  tests/test_egress_provider_registry.py
```

GUI tests set `QT_QPA_PLATFORM=offscreen` before importing PySide6. This prevents macOS AppKit registration aborts when tests are launched by a non-GUI CI or Codex parent process.
