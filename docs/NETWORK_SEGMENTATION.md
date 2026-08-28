# Network Segmentation and Egress Validation

MSAA Network Segmentation performs bounded, explicitly authorized outbound TCP reachability tests. It is an independent Python implementation inspired by the port-specific methodology of [SensePost go-out](https://github.com/sensepost/go-out), which is GPL-3.0. MSAA does not embed, translate, or invoke go-out source code or binaries.

## Safe workflow

1. Obtain written authorization identifying the client, Mac, network segment, permitted destination provider, ports, and testing window.
2. Open **Network Segmentation**.
3. Select an approved provider, enter a small approved TCP port list, scope, and authorization reference.
4. Review the public provider's terms and privacy impact. The provider will observe the source public IP and connection metadata.
5. Confirm authorization and run the test.
6. Export JSON, CSV, TXT, HTML, XLSX, DOCX, or PDF evidence.
7. Compare successful connections with the client-approved egress matrix and independently validate unexpected results in firewall, proxy, DNS, and flow logs.

Tests never start automatically. The engine invokes no shell, sends no application payload, caps a run at 1,024 ports and 16 workers, and constrains per-port timeout to 0.1–10 seconds. The UI defaults to three common ports, four workers, and a two-second timeout.

## Providers and provenance

- SensePost go-out methodology and its referenced `letmeoutofyour.net` and `allports.exposed` services. These are opt-in and must be independently approved for each engagement.
- [PortQuiz](https://portquiz.net/), a public TCP reachability service that documents broad port listening and rate limiting.
- A future internal provider may be added through the provider registry after security and authorization review. Arbitrary destinations are intentionally rejected by the standard UI.

NIST SP 800-41 Rev. 1 supplies firewall policy testing and management context. Provider inclusion is not an endorsement by NIST, CISA, MSAA, or the provider.

## Interpretation

- `reachable`: the TCP handshake succeeded. This demonstrates path reachability only.
- `blocked_or_filtered`: timeout or refusal. This does not prove firewall enforcement; routing, service health, rate limits, proxies, or provider behavior may explain it.
- `resolution_failed`: DNS resolution failed.
- `error`: another bounded local networking error occurred.

Reports include timestamps, target provider, scope, authorization reference, resolved addresses, latency, error code, result hashes, methodology sources, configuration, and limitations. SQLite evidence is stored at `~/Library/Application Support/MSAA/network-segmentation.sqlite3` with owner-only permissions.

## Current limitations

Only TCP connect validation is implemented. UDP, ICMP, application-aware HTTP/TLS, DNS tunneling, proxy policy, packet capture, distributed segment agents, and ingress testing are unsupported. A result covers only the tested Mac and its network path at that time. This feature does not modify firewall or segmentation policy.
