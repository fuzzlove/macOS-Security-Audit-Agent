from __future__ import annotations
import hashlib,ipaddress,os,subprocess,xml.etree.ElementTree as ET
from pathlib import Path

TRUSTED_PATHS=(Path("/opt/homebrew/bin/nmap"),Path("/usr/local/bin/nmap"),Path("/usr/bin/nmap"))
class NmapBackend:
    def discover(self)->Path|None:
        return next((path for path in TRUSTED_PATHS if path.is_file() and os.access(path,os.X_OK)),None)
    def identity(self)->dict:
        path=self.discover()
        if path is None:return {"available":False,"error":"NMAP_NOT_INSTALLED"}
        return {"available":True,"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    def build_arguments(self,addresses:list[str],ports:list[int],*,ipv6:bool=False,udp:bool=False)->list[str]:
        path=self.discover()
        if path is None:raise FileNotFoundError("NMAP_NOT_INSTALLED")
        if not addresses or any(item.startswith("-") for item in addresses):raise ValueError("invalid pinned target list")
        if not ports or len(ports)>65535 or any(not 1<=int(port)<=65535 for port in ports):raise ValueError("invalid port list")
        return [str(path),"-6" if ipv6 else "-n","-sU" if udp else "-sT","--reason","-oX","-","-p",",".join(str(int(port)) for port in ports),"--",*addresses]
    def build_profile_arguments(self,target:str,authorized_cidr:str,profile,*,explicit_high_traffic:bool=False)->list[str]:
        path=self.discover()
        if path is None:raise FileNotFoundError("NMAP_NOT_INSTALLED")
        scope=ipaddress.ip_network(authorized_cidr,strict=False);network=ipaddress.ip_network(target,strict=False)
        if network.version!=scope.version or not network.subnet_of(scope):raise PermissionError("OUT_OF_SCOPE_REJECTED")
        if network.num_addresses>4096:raise ValueError("target scope exceeds the 4096-address safety limit")
        base=network.network_address
        if base.is_multicast or base.is_link_local or base.is_loopback or base.is_unspecified:raise PermissionError("special-use target rejected")
        if profile.profile_id=="full_tcp" and not explicit_high_traffic:raise PermissionError("full TCP range requires explicit high-traffic approval")
        args=[str(path),"-n","--reason","--max-retries","2","--max-rate","100","-oX","-"]
        if network.version==6:args.append("-6")
        if profile.scan_type=="tcp":args.append("-sT")
        elif profile.scan_type in {"udp","dns"}:args.append("-sU")
        elif profile.scan_type in {"icmp","icmpv6"}:args.extend(["-sn","-PE"])
        elif profile.scan_type=="ip_protocol":args.append("-sO")
        else:raise ValueError("unsupported profile scan type")
        if profile.top_ports:args.extend(["--top-ports",str(profile.top_ports)])
        elif profile.ports:args.extend(["-p",",".join(str(port) for port in profile.ports)])
        args.extend(["--",str(network)])
        return args
    def run(self,args:list[str],timeout_seconds:float)->tuple[int,bytes,bytes]:
        if not args or Path(args[0]) not in TRUSTED_PATHS:raise PermissionError("untrusted Nmap executable")
        result=subprocess.run(args,capture_output=True,timeout=min(max(timeout_seconds,1),3600),shell=False,check=False)
        return result.returncode,result.stdout,result.stderr[:65536]
    @staticmethod
    def parse_xml(data:bytes)->ET.Element:
        if len(data)>16*1024*1024:raise ValueError("Nmap XML exceeds size limit")
        upper=data.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:raise ValueError("unsafe XML declaration rejected")
        return ET.fromstring(data)
    @classmethod
    def summarize_xml(cls,data:bytes)->list[dict]:
        root=cls.parse_xml(data);rows=[]
        for host in root.findall("host"):
            address=host.find("address");target=address.get("addr","") if address is not None else ""
            for port in host.findall("./ports/port"):
                state=port.find("state");raw=state.get("state","unknown") if state is not None else "unknown";reason=state.get("reason","") if state is not None else ""
                inferred="INFERRED_ALLOWED" if raw in {"open","closed"} else "INDETERMINATE"
                rows.append({"target":target,"protocol":port.get("protocol",""),"port":int(port.get("portid","0")),"scanner_state":raw,"reason":reason,"segmentation_result":inferred})
        return rows
