# Network Sentinel Feature Matrix

| Feature | Sentinel implementation | Existing MSAA equivalent | Status | Target MSAA module | Tests required |
| --- | --- | --- | --- | --- | --- |
| Active network connections | `collectors/network_connections.py` using `lsof` | Partial localhost/Nmap artifacts | Import/adapt | `network_intelligence/connections.py` | parse lsof, normalize, store |
| Listening ports | `collectors/listening_ports.py` using `lsof` | localhost port scan and Nmap | Import/adapt | `network_intelligence/ports.py` | parse listeners, risk, store |
| Process-to-connection mapping | `lsof` process, pid, user fields | Existing scan artifacts do not normalize live owners | Import/adapt | `network_intelligence/models.py` | owner fields preserved |
| DNS state | DNS/cache collectors | Limited report artifacts | Import/adapt | `network_intelligence/dns.py` | parse `scutil --dns` |
| Gateway/router state | `routes.py` | Network discovery scope detection | Import/adapt | `network_intelligence/dns_gateway.py` | parse default route |
| VPN state | Interface heuristics | Monitor settings only | Import/adapt | `network_intelligence/vpn_proxy.py` | VPN interface sample |
| Proxy state | Network setup helpers | None centralized | Import/adapt | `network_intelligence/vpn_proxy.py` | proxy sample output |
| Local network discovery | Sentinel discovery concepts | Existing MSAA discovery | Already exists | `network_discovery.py` plus UI action | no duplicate scanner |
| New IP/interface assignment | Interface collector | Partial network discovery | Import/adapt | `network_intelligence/posture.py` | posture normalization |
| New remote endpoint detection | Baseline comparison | Baseline drift system | Import/adapt | `network_intelligence/baseline.py` | new endpoint drift |
| New listener detection | Baseline comparison | Port scan deltas | Import/adapt | `network_intelligence/baseline.py` | listener drift |
| Suspicious port detection | Rule/scoring modules | Some local scan findings | Replace existing network-specific scoring | `network_intelligence/risk_scoring.py` | high-risk ports |
| Nmap integration | Optional scanner concepts | Existing MSAA Nmap wrapper | Already exists | `nmap_wrapper.py`, UI action | missing nmap graceful |
| Baseline comparison | `detection/baselines.py` | MSAA baseline drift | Import/adapt | `network_intelligence/baseline.py` | DNS/gateway/listener drift |
| Network timeline | Sentinel history panel | MSAA security timeline | Replace UI, adapt events | `network_intelligence/timeline.py` | events created |
| Alerts | Sentinel alerts panel | MSAA alert pipeline | Replace | `timeline.py`, `NotificationManager` path | event reaches monitor DB |
| Reporting | Sentinel JSON/HTML/CSV | MSAA reports | Replace/adapt | `network_intelligence/report.py` | network report payload |
| Diagnostics | Sentinel app state | MSAA diagnostic panels | Import/adapt | `network_intelligence/diagnostics.py` | failure stage visible |
| Packet capture | Sentinel packet capture panel | MSAA packet capture | Skip default path | existing packet capture module | explicit authorization only |
| Reputation lookups | Sentinel reputation hooks | None | Future | future enrichment | privacy-gated tests |

Integration status summary: active read-only collection, normalization, risk scoring, baseline drift, storage, native UI, diagnostics, and monitor-event routing are native MSAA paths. Standalone Sentinel UI, CLI, database, and report writers are not used.
