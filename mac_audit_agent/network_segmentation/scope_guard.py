from __future__ import annotations
import ipaddress
from datetime import datetime,timezone
from .ingress_models import Engagement,ExpectedFlow

class ScopeViolation(PermissionError):pass

def _inside(address:str,cidrs:tuple[str,...])->bool:
    ip=ipaddress.ip_address(address.split("%",1)[0]);return any(ip in ipaddress.ip_network(cidr,strict=False) for cidr in cidrs)

def validate_target(engagement:Engagement,flow:ExpectedFlow,address:str,*,now:datetime|None=None)->None:
    if not engagement.acknowledgement:raise ScopeViolation("operator authorization acknowledgement is required")
    current=now or datetime.now(timezone.utc);start=datetime.fromisoformat(engagement.starts_at);end=datetime.fromisoformat(engagement.ends_at)
    if current<start or current>end:raise ScopeViolation("test lease is outside the authorized window")
    ip=ipaddress.ip_address(address.split("%",1)[0])
    if ip.version!=flow.address_family:raise ScopeViolation("address family is not approved by the flow")
    if not _inside(address,engagement.destination_cidrs):raise ScopeViolation("destination is outside authorized CIDRs")
    if _inside(address,engagement.excluded_cidrs):raise ScopeViolation("destination is explicitly excluded")
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:raise ScopeViolation("special-use destination is blocked by the safe profile")
    for network in engagement.destination_cidrs:
        net=ipaddress.ip_network(network,strict=False)
        if ip.version==4 and ip in {net.network_address,net.broadcast_address}:raise ScopeViolation("network and broadcast addresses are blocked")
    if flow.protocol.lower() in {item.lower() for item in engagement.restricted_protocols}:raise ScopeViolation("protocol is restricted by the engagement")
    if flow.protocol.lower() not in {"tcp","udp","icmp","icmpv6","sctp","ip"}:raise ScopeViolation("unsupported protocol")
    if flow.port_start is not None and not 1<=flow.port_start<=65535:raise ScopeViolation("invalid port")
    if flow.port_end is not None and (flow.port_start is None or not flow.port_start<=flow.port_end<=65535):raise ScopeViolation("invalid port range")

def validate_resolution(engagement:Engagement,flow:ExpectedFlow,pinned:tuple[str,...],current:tuple[str,...])->None:
    if set(pinned)!=set(current):
        for address in current:validate_target(engagement,flow,address)
        raise ScopeViolation("DNS answers changed after plan approval; review and repin before execution")
