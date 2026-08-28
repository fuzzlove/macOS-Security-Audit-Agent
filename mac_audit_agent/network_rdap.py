from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


PROVIDERS = {
    "ARIN bootstrap": ("https://rdap.arin.net/bootstrap/ip/", {"rdap.arin.net", "rdap.db.ripe.net"}),
    "RIPE": ("https://rdap.db.ripe.net/ip/", {"rdap.db.ripe.net"}),
}


@dataclass(frozen=True)
class RDAPAddressResult:
    address: str; requested_provider: str; authoritative_host: str; name: str; handle: str; start_address: str; end_address: str; country: str; entity_names: tuple[str,...]; status: tuple[str,...]; retrieved_at: str; source_url: str; qualification: str
    def to_dict(self)->dict[str,Any]:return asdict(self)


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts:set[str]):super().__init__();self.allowed_hosts=allowed_hosts
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlsplit(newurl)
        if parsed.scheme!="https" or parsed.hostname not in self.allowed_hosts or parsed.username or parsed.password or parsed.port not in {None,443}:raise urllib.error.URLError("RDAP redirect target is not allowlisted")
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def _entity_names(payload:dict)->tuple[str,...]:
    names=[]
    for entity in payload.get("entities",[])[:100]:
        if not isinstance(entity,dict):continue
        vcard=entity.get("vcardArray",[])
        if isinstance(vcard,list) and len(vcard)>1 and isinstance(vcard[1],list):
            for field in vcard[1]:
                if isinstance(field,list) and len(field)>3 and field[0] in {"fn","org"}:
                    value=str(field[3])[:300]
                    if value and value not in names:names.append(value)
    return tuple(names[:30])


def lookup_ip_rdap(address:str,provider:str,*,timeout:float=8,max_bytes:int=2*1024*1024)->RDAPAddressResult:
    ip=str(ipaddress.ip_address(address.strip().split("%",1)[0])); parsed_ip=ipaddress.ip_address(ip)
    if not parsed_ip.is_global:raise ValueError("RDAP lookup is limited to public global IP addresses.")
    try:base,hosts=PROVIDERS[provider]
    except KeyError as exc:raise ValueError("Unsupported RDAP provider.") from exc
    url=base+urllib.parse.quote(ip,safe=":"); request=urllib.request.Request(url,headers={"Accept":"application/rdap+json","User-Agent":"MSAA-RDAP/1.0"},method="GET"); opener=urllib.request.build_opener(_RedirectHandler(hosts))
    with opener.open(request,timeout=timeout) as response:
        final=urllib.parse.urlsplit(response.geturl());
        if final.scheme!="https" or final.hostname not in hosts:raise ValueError("RDAP response came from an unauthorized host.")
        raw=response.read(max_bytes+1)
        if len(raw)>max_bytes:raise ValueError("RDAP response exceeded the size limit.")
    try:payload=json.loads(raw)
    except json.JSONDecodeError as exc:raise ValueError("RDAP provider returned invalid JSON.") from exc
    if not isinstance(payload,dict) or not payload.get("rdapConformance"):raise ValueError("RDAP response schema was not recognized.")
    return RDAPAddressResult(ip,provider,final.hostname or "",str(payload.get("name", ""))[:300],str(payload.get("handle", ""))[:300],str(payload.get("startAddress", ""))[:100],str(payload.get("endAddress", ""))[:100],str(payload.get("country", ""))[:20],_entity_names(payload),tuple(str(v)[:100] for v in payload.get("status",[])[:30]),datetime.now(timezone.utc).isoformat(),response.geturl(),"Registration data identifies address-space records, not the operator of a specific connection and not maliciousness or client approval.")
