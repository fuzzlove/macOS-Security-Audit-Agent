from __future__ import annotations
import ipaddress, re, socket
from .errors import FirewallError
from .models import AddressSelector, FirewallPolicy, PortRange

SAFE_ID=re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$"); SAFE_INTERFACE=re.compile(r"^[a-zA-Z0-9_.:-]{1,32}$"); PROTOCOLS={"tcp","udp","icmp","icmp6","gre","esp","ah"}
SERVICES={"ssh":22,"domain":53,"dns":53,"http":80,"https":443,"ntp":123,"dhcp":67}
def normalize_domain(value: str) -> str:
    value=value.strip().rstrip(".")
    try: encoded=value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc: raise FirewallError("FW007",f"Invalid IDNA domain: {exc}") from exc
    if len(encoded)>253 or "." not in encoded or any(not label or len(label)>63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",label) for label in encoded.split(".")): raise FirewallError("FW007","Malformed domain labels or unqualified hostname.")
    return encoded
def parse_ports(value: str) -> tuple[PortRange,...]:
    if not value.strip(): return ()
    result=[]
    for token in value.replace("-",":").split(","):
        token=token.strip().lower()
        if token in SERVICES: result.append(PortRange(SERVICES[token],SERVICES[token])); continue
        parts=token.split(":")
        if len(parts)>2 or any(not p.isdigit() for p in parts): raise FirewallError("FW011",f"Invalid port: {token}")
        start=int(parts[0]); end=int(parts[-1])
        if not 1<=start<=end<=65535: raise FirewallError("FW011",f"Port or range outside 1–65535: {token}")
        result.append(PortRange(start,end))
    return tuple(sorted(set(result)))
def normalize_ips(lines: list[str], family: int|None=None, limit: int=100000):
    networks=[]
    for raw in lines:
        token=raw.split("#",1)[0].strip()
        if not token: continue
        try: net=ipaddress.ip_network(token,strict=False)
        except ValueError as exc: raise FirewallError("FW009" if ":" not in token else "FW010",str(exc)) from exc
        if family and net.version!=family: raise FirewallError("FW009" if family==4 else "FW010","Address family mismatch.")
        networks.append(net)
        if len(networks)>limit: raise FirewallError("FW023","Table entry limit exceeded.")
    return tuple(str(n) for n in ipaddress.collapse_addresses(networks))
def validate_selector(selector: AddressSelector):
    if selector.kind in {"address","network"}: normalize_ips(list(selector.values))
    elif selector.kind=="table" and any(not SAFE_ID.fullmatch(v) for v in selector.values): raise FirewallError("FW006","Unsafe PF table name.")
def validate_policy(policy: FirewallPolicy) -> tuple[str,...]:
    if not SAFE_ID.fullmatch(policy.policy_id): raise FirewallError("FW006","Unsafe policy identifier.")
    warnings=[]; seen=set()
    for rule in policy.rules:
        if not SAFE_ID.fullmatch(rule.rule_id) or rule.rule_id in seen: raise FirewallError("FW006","Invalid or duplicate rule identifier.")
        seen.add(rule.rule_id)
        if any(p not in PROTOCOLS for p in rule.protocols): raise FirewallError("FW012","Unsupported protocol.")
        if any(not SAFE_INTERFACE.fullmatch(i) for i in rule.interfaces): raise FirewallError("FW024","Unsafe interface name.")
        validate_selector(rule.source); validate_selector(rule.destination)
        if rule.destination_ports and not set(rule.protocols)&{"tcp","udp"}: raise FirewallError("FW006","Ports require TCP or UDP.")
        if rule.action=="block" and rule.direction in {"out","both"} and rule.source.kind==rule.destination.kind=="any" and not rule.protocols: warnings.append("FW013: Broad outbound block may interrupt all connectivity; rollback confirmation is required.")
    return tuple(warnings)
