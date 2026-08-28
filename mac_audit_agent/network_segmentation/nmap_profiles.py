from __future__ import annotations
from dataclasses import dataclass

TCP_COMMON=(20,21,22,23,25,53,80,88,110,111,135,137,138,139,143,389,443,445,465,514,587,636,993,995,1433,1521,2049,2375,2376,3260,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,9200,10250,11211,27017)
UDP_COMMON=(53,67,68,69,88,111,123,137,138,161,162,389,500,514,623,1434,1812,1813,1900,2049,4500,4789,5353,5683,11211)
@dataclass(frozen=True)
class NmapProfile:
    profile_id:str;name:str;scan_type:str;ports:tuple[int,...]=();top_ports:int|None=None;requires_privilege:bool=False;warning:str=""

PROFILES=(
 NmapProfile("safe_tcp_common","Safe TCP Common","tcp",TCP_COMMON),
 NmapProfile("tcp_top_100","TCP Top 100","tcp",top_ports=100),
 NmapProfile("tcp_top_1000","TCP Top 1000","tcp",top_ports=1000),
 NmapProfile("full_tcp","Full TCP 1-65535","tcp",tuple(range(1,65536)),warning="High traffic and long duration; explicit approval required."),
 NmapProfile("safe_udp_common","Safe UDP Common","udp",UDP_COMMON,requires_privilege=True,warning="UDP scanner states can be ambiguous without observer evidence."),
 NmapProfile("udp_top_50","UDP Top 50","udp",top_ports=50,requires_privilege=True),
 NmapProfile("dns_path","DNS Egress/Ingress Path (TCP and UDP 53)","dns",(53,),requires_privilege=True,warning="Tests port reachability only; it does not transmit tunneled or exfiltration content."),
 NmapProfile("icmp","ICMP Reachability","icmp",requires_privilege=True),
 NmapProfile("icmpv6","ICMPv6 Reachability","icmpv6",requires_privilege=True,warning="This tests approved echo reachability only and does not justify blanket ICMPv6 blocking."),
 NmapProfile("extended_protocols","Extended IP Protocols","ip_protocol",(4,6,17,41,47,50,51,58,132),requires_privilege=True,warning="Path inference only; ambiguous without destination-observer evidence."),
)
def profile_by_id(profile_id:str)->NmapProfile:
    for profile in PROFILES:
        if profile.profile_id==profile_id:return profile
    raise ValueError("unknown fixed Nmap profile")
