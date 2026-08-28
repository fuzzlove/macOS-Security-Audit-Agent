# Egress Test Providers

MSAA registers six independently configurable public test providers: `letmeoutofyour.net`, `portquiz.net`, `egresser.labs.cyberis.co.uk`, `tcpbin.com`, `tcpbin.org`, and `allports.exposed`. Registry entries describe intended capabilities, not current availability. MSAA does not embed historical IP addresses and never infers an RIR from a hostname, TLD, country, or hosting brand.

## Current implementation status

- Completed: versioned provider/service models, all six registry entries, compatibility aliases, safe hostname validation, runtime A/AAAA resolution, rejection of loopback/private/link-local/multicast/reserved destinations, nonce generation and exact echo validation, RDAP response parsing, explicit RIR filtering, bounded qualification states/expiry, structured evidence compatibility, and asynchronous GUI presentation.
- Completed: `egresser` and `allports.exposed` default to disabled/unqualified and cannot be actively selected from the current panel before qualification.
- Partial: the existing authorized generic test executes bounded TCP connect probes. A handshake is recorded only as reachability and never as full application validation.
- Not yet wired to active testing: provider-specific UDP echo, TLS echo, mutual TLS, live RDAP acquisition/referrals, qualification persistence, cancellation/resume, randomized/full-range presets, and cross-provider policy conclusions. The schema represents these services, but the UI does not claim they ran.
- Untested: current public-provider availability. Deterministic CI makes no public network requests.

## Safety and interpretation

Every run requires a written authorization reference and scope. Ordinary and custom-range runs are capped at 1,024 unique ports. Providers declaring broad-port capability expose an explicit **Full TCP range (ports 1–65535)** option. It requires a separate confirmation for every run and uses batches of at most 256 submitted probes to bound the work queue. The warning explains traffic volume, duration, authorization, rate-limiting risk, and recommends sampling for routine checks. Public endpoint failure is `INCONCLUSIVE`: DNS, routing, rate limiting, maintenance, protocol mismatch, and provider failure can resemble local filtering. Do not label egress blocked from one provider timeout.

Runtime resolution must occur immediately before a provider-specific probe. If any answer is private, loopback, link-local, multicast, unspecified, or reserved, the target set is rejected to mitigate configuration abuse and DNS rebinding. Private testing belongs in a separately authorized internal-testing mode.

RDAP data is evidence with a lookup timestamp. `ARIN`, `RIPE NCC`, `APNIC`, `AFRINIC`, and `LACNIC` labels must come from authoritative/referral metadata. When no qualified address matches an operator-selected RIR, return `NO_QUALIFIED_DESTINATION_FOR_RIR`; never silently substitute another registry.

## Qualification lifecycle

States are `UNKNOWN`, `RESOLVING`, `UNQUALIFIED`, `QUALIFYING`, `HEALTHY`, `DEGRADED`, `FAILED`, and `DISABLED`. A healthy result requires DNS, transport, expected application response, and RDAP classification. Defaults are 24 hours healthy, 4 hours degraded, and 30 minutes before retrying a failed provider. DNS success alone is never health.

## Running tests

```sh
.venv/bin/python -m pytest -q tests/test_network_segmentation.py tests/test_egress_provider_registry.py
```

Launch MSAA using the repository launcher, then open **Network Segmentation**:

```sh
.venv/bin/python launcher.py
```

Live public testing is operator initiated and must not be part of deterministic CI.
