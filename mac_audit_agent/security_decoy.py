from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


DECOY_EVENT_TYPE = "security_decoy_triggered"
DECOY_ALERT_INTERVAL_SECONDS = 300


BANNERS = {
    "ftp": b"220 Security research decoy service ready\r\n",
    "http": b"HTTP/1.1 200 OK\r\nServer: research-decoy\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSecurity research decoy service.\n",
    "ssh": b"SSH-2.0-ResearchDecoy_1.0\r\n",
    "generic": b"Security research decoy service.\r\n",
}


@dataclass
class DecoyConfig:
    listen_address: str = "127.0.0.1"
    port: int = 0
    protocol_profile: str = "generic"
    timeout_seconds: float = 2.0
    alert_interval_seconds: int = DECOY_ALERT_INTERVAL_SECONDS
    severity: str = "medium"


class SecurityResearchDecoyService:
    def __init__(self, db: AuditDatabase, config: DecoyConfig | None = None) -> None:
        self.db = db
        self.config = config or DecoyConfig()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._active_connections = 0
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._socket is not None)

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active_connections

    @property
    def bound_port(self) -> int:
        if not self._socket:
            return int(self.config.port)
        try:
            return int(self._socket.getsockname()[1])
        except Exception:
            return int(self.config.port)

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.listen_address, int(self.config.port)))
        sock.listen(20)
        sock.settimeout(0.5)
        self._socket = sock
        self._thread = threading.Thread(target=self._serve, name="security-research-decoy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        sock = self._socket
        self._socket = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "listen_address": self.config.listen_address,
            "port": self.bound_port,
            "protocol_profile": self.config.protocol_profile,
            "active_connections": self.active_connections,
        }

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            sock = self._socket
            if sock is None:
                return
            try:
                client, address = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._handle_client, args=(client, address), daemon=True)
            thread.start()

    def _handle_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        with self._lock:
            self._active_connections += 1
        bytes_sent = 0
        bytes_received = 0
        source_ip, source_port = address[0], int(address[1])
        timestamp = utc_now_iso()
        try:
            client.settimeout(float(self.config.timeout_seconds))
            banner = BANNERS.get(self.config.protocol_profile, BANNERS["generic"])
            bytes_sent = client.send(banner)
            try:
                data = client.recv(4096)
                bytes_received = len(data or b"")
            except socket.timeout:
                bytes_received = 0
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
            with self._lock:
                self._active_connections = max(0, self._active_connections - 1)
        self._record_connection(
            timestamp=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
        )

    def _record_connection(self, *, timestamp: str, source_ip: str, source_port: int, bytes_sent: int, bytes_received: int) -> None:
        destination_port = self.bound_port
        profile = self.config.protocol_profile
        correlation_id = self._correlation_id(source_ip, profile, destination_port)
        previous = [
            item
            for item in self.db.list_security_decoy_connections(limit=1000)
            if item.get("source_ip") == source_ip and item.get("protocol_profile") == profile and int(item.get("destination_port") or 0) == destination_port
        ]
        first_seen = min([str(item.get("first_seen", "")) for item in previous if item.get("first_seen")] + [timestamp])
        connection_count = sum(int(item.get("connection_count") or 1) for item in previous) + 1
        payload = {
            "connection_id": f"decoy-{uuid4()}",
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "listen_address": self.config.listen_address,
            "protocol_profile": profile,
            "bytes_sent": int(bytes_sent),
            "bytes_received": int(bytes_received),
            "connection_count": connection_count,
            "first_seen": first_seen,
            "last_seen": timestamp,
            "correlation_id": correlation_id,
            "payload_json": {
                "static_banner_only": True,
                "no_authentication": True,
                "no_command_execution": True,
                "no_filesystem_access": True,
            },
        }
        self.db.record_security_decoy_connection(payload)
        if self._alert_allowed(source_ip, profile):
            event = BackgroundMonitorEvent(
                event_id=f"security-decoy-{uuid4()}",
                timestamp=timestamp,
                event_type=DECOY_EVENT_TYPE,
                severity=self.config.severity,
                source="security_research_decoy",
                evidence=f"Security decoy connection from {source_ip}:{source_port} to local port {destination_port} using {profile}; grouped_count={connection_count}",
                confidence="high",
                recommendation="Review whether this source is expected. Do not retaliate or attempt to exploit the source.",
                metadata_json=json.dumps(payload, sort_keys=True),
                related_network_endpoint=f"{source_ip}:{source_port}",
                correlation_id=correlation_id,
                trigger_source="security_research_decoy",
                trigger_subsource="tcp_static_banner_listener",
                raw_signal_summary=f"TCP connection to decoy listener from {source_ip}:{source_port}",
                normalized_signal=f"decoy:{profile}:{source_ip}:{destination_port}",
                first_seen=first_seen,
                last_seen=timestamp,
            )
            self.db.record_monitor_event(event, dedupe_window_seconds=0)

    def _alert_allowed(self, source_ip: str, profile: str) -> bool:
        key = f"security_decoy_last_alert:{source_ip}:{profile}"
        raw_last = self.db.get_background_monitor_state(key, "")
        now = time.time()
        try:
            last = float(raw_last)
        except (TypeError, ValueError):
            last = 0.0
        if now - last < int(self.config.alert_interval_seconds):
            return False
        self.db.set_background_monitor_state(key, str(now))
        return True

    @staticmethod
    def _correlation_id(source_ip: str, profile: str, destination_port: int) -> str:
        return hashlib.sha256(f"security-decoy:{source_ip}:{profile}:{destination_port}".encode("utf-8")).hexdigest()[:16]
