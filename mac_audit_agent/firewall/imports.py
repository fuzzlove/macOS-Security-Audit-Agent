from __future__ import annotations
import csv, hashlib, io, ipaddress, json
from dataclasses import dataclass
from .validator import normalize_domain, normalize_ips, parse_ports
@dataclass(frozen=True)
class ImportSummary:
    total_lines:int; accepted:tuple[str,...]; duplicates:int; invalid:tuple[str,...]; comments:int; ipv4:int; ipv6:int; domains:int; source_hash:str
def parse_list(text:str,kind:str="mixed",limit:int=100000):
    accepted=[]; invalid=[]; comments=0
    for raw in text.splitlines()[:limit+1]:
        line=raw.strip()
        if not line or line.startswith("#"): comments+=bool(line); continue
        token=line.split("#",1)[0].strip().split()[-1]
        try:
            if kind=="domain": value=normalize_domain(token)
            elif kind=="ports": value=",".join(p.render() for p in parse_ports(token))
            else:
                try: value=str(ipaddress.ip_network(token,strict=False))
                except ValueError: value=normalize_domain(token)
            accepted.append(value)
        except Exception: invalid.append(token)
    if len(text.splitlines())>limit: invalid.append("<entry limit exceeded>")
    unique=tuple(dict.fromkeys(accepted)); ipv4=sum("." in x and "/" in x or x.replace(".","").isdigit() for x in unique); ipv6=sum(":" in x for x in unique); domains=len(unique)-ipv4-ipv6
    return ImportSummary(len(text.splitlines()),unique,len(accepted)-len(unique),tuple(invalid),comments,ipv4,ipv6,domains,hashlib.sha256(text.encode()).hexdigest())
