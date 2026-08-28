from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .degraded_observer import DegradedFileEvent, DegradedFilesystemObserver

PROTOTYPE_SCHEMA_VERSION = "1.0"
DEFAULT_STATE_DIRECTORY = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "AntiRansomwarePrototype"


@dataclass(frozen=True)
class PrototypeObserverStatus:
    running: bool
    mode: str
    root: str
    started_at: str
    heartbeat_at: str
    events_observed: int
    events_dropped: int
    scan_overflow: bool
    production_endpoint_security_active: bool
    containment_available: bool
    limitations: tuple[str, ...]
    health_path: str
    event_journal_path: str
    schema_version: str = PROTOTYPE_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)


class PrototypeRansomwareObserver:
    """Lifecycle owner for the explicit-scope development observer.

    Only operation, size, timing, and keyed path tokens are journaled. This
    observer neither attributes processes nor blocks, pauses, or deletes files.
    """

    def __init__(
        self,
        root: Path,
        *,
        state_directory: Path = DEFAULT_STATE_DIRECTORY,
        interval_seconds: float = 0.25,
        max_files: int = 10_000,
        queue_size: int = 1_024,
        heartbeat_seconds: float = 2.0,
        event_callback: Callable[[DegradedFileEvent], None] | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.state_directory = Path(state_directory)
        self.health_path = self.state_directory / "health.json"
        self.event_path = self.state_directory / "events.jsonl"
        self._salt_path = self.state_directory / "path-token.key"
        self._heartbeat_seconds = max(0.25, heartbeat_seconds)
        self._started_at = ""
        self._events_observed = 0
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._salt = b""
        self._event_callback = event_callback
        self.observer = DegradedFilesystemObserver(
            self.root, self._record_event, interval_seconds=interval_seconds,
            max_files=max_files, queue_size=queue_size,
        )

    @property
    def running(self) -> bool:
        return self.observer.running and bool(self._heartbeat_thread and self._heartbeat_thread.is_alive())

    def start(self) -> PrototypeObserverStatus:
        if self.running:
            return self.status()
        if not self.root.is_dir():
            raise ValueError("prototype observation root must be an existing directory")
        self.state_directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_directory, 0o700)
        self._salt = self._load_or_create_salt()
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._events_observed = 0
        self._stop.clear()
        self.observer.start()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, name="MSAAARPrototypeHeartbeat", daemon=True)
        self._heartbeat_thread.start()
        self._write_health()
        return self.status()

    def stop(self, timeout: float = 3.0) -> PrototypeObserverStatus:
        self._stop.set()
        self.observer.stop(timeout)
        thread = self._heartbeat_thread
        if thread: thread.join(timeout)
        self._heartbeat_thread = None if not thread or not thread.is_alive() else thread
        self._write_health()
        return self.status()

    def status(self) -> PrototypeObserverStatus:
        return PrototypeObserverStatus(
            running=self.running,
            mode="DEVELOPMENT_OBSERVATION_ONLY",
            root=str(self.root),
            started_at=self._started_at,
            heartbeat_at=datetime.now(timezone.utc).isoformat(),
            events_observed=self._events_observed,
            events_dropped=self.observer.dropped_events,
            scan_overflow=self.observer.scan_overflow,
            production_endpoint_security_active=False,
            containment_available=False,
            limitations=(
                "Delayed filesystem metadata observation only.",
                "No reliable responsible-process or root attribution.",
                "No preemptive authorization, blocking, or containment.",
                "Observation stops when this MSAA process exits.",
            ),
            health_path=str(self.health_path),
            event_journal_path=str(self.event_path),
        )

    def _load_or_create_salt(self) -> bytes:
        try:
            value = self._salt_path.read_bytes()
            if len(value) == 32: return value
        except OSError:
            pass
        value = os.urandom(32)
        self._salt_path.write_bytes(value); os.chmod(self._salt_path, 0o600)
        return value

    def _path_token(self, path: str) -> str:
        relative = str(Path(path).resolve().relative_to(self.root))
        return hashlib.sha256(self._salt + relative.encode("utf-8", "surrogateescape")).hexdigest()

    def _record_event(self, event: DegradedFileEvent) -> None:
        record = {
            "schema_version": PROTOTYPE_SCHEMA_VERSION,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "operation": event.operation,
            "path_token": self._path_token(event.path),
            "size": event.size,
            "mtime_ns": event.mtime_ns,
            "prototype": True,
            "containment_performed": False,
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with self.event_path.open("a", encoding="utf-8") as handle: handle.write(encoded)
            os.chmod(self.event_path, 0o600)
            self._events_observed += 1
            self._write_health()
        if self._event_callback is not None:
            self._event_callback(event)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self._heartbeat_seconds):
            self._write_health()

    def _write_health(self) -> None:
        if not self.state_directory.exists(): return
        payload = self.status().to_dict()
        temporary = self.health_path.with_suffix(".tmp")
        with self._lock:
            temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.health_path)


def read_prototype_status(path: Path = DEFAULT_STATE_DIRECTORY / "health.json", *, maximum_age_seconds: float = 10.0) -> dict:
    try:
        info = path.lstat()
        if not info.st_mode & 0o170000 == 0o100000 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return {"running": False, "health_state": "untrusted"}
        payload = json.loads(path.read_text(encoding="utf-8"))
        heartbeat = datetime.fromisoformat(str(payload["heartbeat_at"]))
        age = (datetime.now(timezone.utc) - heartbeat.astimezone(timezone.utc)).total_seconds()
        payload["running"] = bool(payload.get("running")) and 0 <= age <= maximum_age_seconds
        payload["health_state"] = "fresh" if payload["running"] else "stale"
        return payload
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"running": False, "health_state": "unavailable"}
