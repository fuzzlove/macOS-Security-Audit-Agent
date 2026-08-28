from __future__ import annotations
import socket,time
from dataclasses import dataclass
from threading import Event

@dataclass(frozen=True)
class NativeResult:
    state:str;latency_ms:float|None;response:str;error:str=""

class NativeSocketBackend:
    """Bounded native probes; never invokes a shell or interprets payloads."""
    def __init__(self,cancel_event:Event|None=None):self.cancel_event=cancel_event or Event()
    def tcp_connect(self,address:str,port:int,timeout:float=1.5)->NativeResult:
        if self.cancel_event.is_set():return NativeResult("cancelled",None,"cancelled")
        started=time.monotonic();family=socket.AF_INET6 if ":" in address else socket.AF_INET
        sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(min(max(timeout,.1),10.0))
        try:
            code=sock.connect_ex((address,port));latency=round((time.monotonic()-started)*1000,3)
            if code==0:return NativeResult("connected",latency,"connected")
            if code in {61,111}:return NativeResult("rejected",latency,"tcp_rst")
            return NativeResult("inconclusive",latency,"",f"connect_error_{code}")
        except socket.timeout:return NativeResult("timeout",round((time.monotonic()-started)*1000,3),"","timeout")
        except OSError as exc:return NativeResult("error",None,"",type(exc).__name__)
        finally:sock.close()
    def udp_nonce(self,address:str,port:int,nonce:bytes,timeout:float=1.5)->NativeResult:
        if len(nonce)>512:raise ValueError("UDP nonce exceeds 512-byte safety limit")
        if self.cancel_event.is_set():return NativeResult("cancelled",None,"cancelled")
        family=socket.AF_INET6 if ":" in address else socket.AF_INET;sock=socket.socket(family,socket.SOCK_DGRAM);sock.settimeout(min(max(timeout,.1),10.0));started=time.monotonic()
        try:
            sock.connect((address,port));sock.send(nonce);received=sock.recv(1024);latency=round((time.monotonic()-started)*1000,3)
            return NativeResult("validated" if received==nonce else "validation_failed",latency,"responder_ack" if received==nonce else "unexpected_response")
        except ConnectionRefusedError:return NativeResult("rejected",round((time.monotonic()-started)*1000,3),"icmp_port_unreachable")
        except socket.timeout:return NativeResult("inconclusive",round((time.monotonic()-started)*1000,3),"","no_response")
        finally:sock.close()
