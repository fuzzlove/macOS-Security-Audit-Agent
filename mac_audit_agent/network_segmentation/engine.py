from __future__ import annotations

import hashlib
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Protocol
from uuid import uuid4

from .models import EgressProbe, EgressResult, EgressRun, Provider, utc_now


class ProbeTransport(Protocol):
    def connect(self, hostname: str, port: int, timeout_seconds: float) -> tuple[str, tuple[str, ...], float | None, str]: ...


class SocketProbeTransport:
    """TCP connect only. It sends no application payload and invokes no shell."""

    def connect(self, hostname: str, port: int, timeout_seconds: float) -> tuple[str, tuple[str, ...], float | None, str]:
        started=time.monotonic()
        try:
            records=socket.getaddrinfo(hostname,port,type=socket.SOCK_STREAM)
        except socket.gaierror:
            return "resolution_failed",(),None,"dns_resolution_failed"
        addresses=tuple(sorted({str(record[4][0]) for record in records}))[:16]
        try:
            with socket.create_connection((hostname,port),timeout=timeout_seconds):pass
        except (TimeoutError,socket.timeout):
            return "blocked_or_filtered",addresses,round((time.monotonic()-started)*1000,3),"connect_timeout"
        except ConnectionRefusedError:
            return "blocked_or_filtered",addresses,round((time.monotonic()-started)*1000,3),"connection_refused"
        except OSError as exc:
            return "error",addresses,round((time.monotonic()-started)*1000,3),type(exc).__name__
        return "reachable",addresses,round((time.monotonic()-started)*1000,3),""


class EgressTestEngine:
    MAX_PROBES=1024
    MAX_FULL_RANGE_PROBES=65535
    MAX_WORKERS=16
    SUBMISSION_BATCH_SIZE=256

    def __init__(self, transport: ProbeTransport | None = None) -> None:
        self.transport=transport or SocketProbeTransport()

    def run(self, *, provider: Provider, probes: list[EgressProbe], authorization_reference: str, target_scope: str, timeout_seconds: float=1.5, workers: int=4, authorized: bool=False, full_range_authorized: bool=False) -> EgressRun:
        if not authorized:raise PermissionError("explicit authorized-scope confirmation is required before egress testing")
        if not authorization_reference.strip():raise ValueError("authorization reference is required")
        if not target_scope.strip():raise ValueError("target scope is required")
        if not probes:raise ValueError("at least one probe is required")
        if len(probes)>self.MAX_PROBES:
            if not full_range_authorized:raise PermissionError("more than 1024 probes requires explicit full-range authorization")
            if "broad_ports" not in provider.capabilities:raise ValueError("selected provider does not advertise broad-port testing")
            if len(probes)>self.MAX_FULL_RANGE_PROBES:raise ValueError("full-range testing is limited to 65535 ports")
        if not 0.1<=timeout_seconds<=10:raise ValueError("timeout must be between 0.1 and 10 seconds")
        workers=max(1,min(int(workers),self.MAX_WORKERS,len(probes)))
        for probe in probes:probe.validate()
        run=EgressRun.create(provider,authorization_reference.strip()[:256],target_scope.strip()[:256])
        run.configuration={"timeout_seconds":timeout_seconds,"workers":workers,"probe_count":len(probes),"payload_bytes_sent":0,"full_range_authorized":bool(full_range_authorized),"submission_batch_size":self.SUBMISSION_BATCH_SIZE}
        run.source_methodology=[{"name":"SensePost go-out","url":"https://github.com/sensepost/go-out","use":"Port-specific egress reachability methodology; no source code embedded."},{"name":"NIST SP 800-41 Rev. 1","url":"https://doi.org/10.6028/NIST.SP.800-41r1","use":"Firewall policy testing and management context."}]
        with ThreadPoolExecutor(max_workers=workers,thread_name_prefix="msaa-egress") as pool:
            # Bound queued futures so a 65,535-port run cannot allocate an
            # unbounded work queue. Completed evidence is retained per port.
            for offset in range(0,len(probes),self.SUBMISSION_BATCH_SIZE):
                batch=probes[offset:offset+self.SUBMISSION_BATCH_SIZE]
                futures={pool.submit(self._probe,provider,probe,timeout_seconds):probe for probe in batch}
                for future in as_completed(futures):run.results.append(future.result())
        run.results.sort(key=lambda item:(item.port,item.protocol));run.completed_at=utc_now()
        run.limitations=["A successful TCP handshake shows reachability, not application-layer permission or malicious traffic.","A timeout or refusal does not prove a firewall blocked traffic; routing, DNS, service state, proxies, and provider limits can produce the same result.","Testing observes this Mac's current network path only; other segments and devices may differ.","The compatibility probe path is TCP connect-only. Application validation, UDP, TLS, and mTLS require selecting a provider service; mTLS also requires an explicit test certificate."]
        return run

    def _probe(self,provider:Provider,probe:EgressProbe,timeout:float)->EgressResult:
        started=utc_now();status,addresses,latency,error=self.transport.connect(provider.hostname,probe.port,timeout);completed=utc_now()
        evidence={"provider_id":provider.provider_id,"hostname":provider.hostname,"port":probe.port,"protocol":probe.protocol,"status":status,"started_at":started,"completed_at":completed,"latency_ms":latency,"resolved_addresses":addresses,"error_code":error}
        digest=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        return EgressResult(str(uuid4()),probe.port,probe.protocol,status,started,completed,latency,addresses,error,digest)
