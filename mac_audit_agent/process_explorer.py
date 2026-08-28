from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


SENSITIVE_ENV_RE = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|AUTH|CREDENTIAL|COOKIE|SESSION|PRIVATE_KEY)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_environment(environment: dict[str, Any], *, limit: int = 64) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in list(environment.items())[:limit]:
        name = str(key)[:128]
        redacted[name] = "[REDACTED]" if SENSITIVE_ENV_RE.search(name) else str(value)[:512]
    return redacted


@dataclass
class ProcessRecord:
    identity: str
    pid: int
    ppid: int | None
    responsible_pid: int | None
    uid: int | None
    user: str
    name: str
    path: str
    arguments: list[str]
    state: str = "running"
    event: str = "snapshot"
    started_at: str = ""
    observed_at: str = field(default_factory=_now)
    exited_at: str = ""
    exit_status: int | None = None
    architecture: str = "unknown"
    signing_id: str = ""
    team_id: str = ""
    platform_binary: bool = False
    code_signing_flags: int | None = None
    cdhash: str = ""
    ancestry: list[dict[str, Any]] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    cpu_percent: float | None = None
    memory_percent: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def process_identity(pid: int, started_at: str, path: str) -> str:
    material = f"{pid}\0{started_at}\0{path}".encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()[:24]


def collect_process_snapshot(executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> tuple[list[ProcessRecord], str]:
    command = ["/bin/ps", "-axo", "pid=,ppid=,uid=,user=,state=,%cpu=,%mem=,lstart=,comm="]
    try:
        result = executor(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"unavailable: {exc}"
    if result.returncode != 0:
        return [], f"unavailable: {(result.stderr or '').strip() or 'ps failed'}"
    records: list[ProcessRecord] = []
    # lstart is five whitespace-delimited fields; comm consumes the remainder.
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 12)
        if len(parts) < 13:
            continue
        try:
            pid, ppid, uid = int(parts[0]), int(parts[1]), int(parts[2])
            cpu, memory = float(parts[5]), float(parts[6])
            started = datetime.strptime(" ".join(parts[7:12]), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, TypeError):
            continue
        path = parts[12]
        records.append(
            ProcessRecord(
                identity=process_identity(pid, started, path),
                pid=pid,
                ppid=ppid,
                responsible_pid=None,
                uid=uid,
                user=parts[3],
                name=path.rsplit("/", 1)[-1],
                path=path,
                arguments=[path],
                started_at=started,
                cpu_percent=cpu,
                memory_percent=memory,
            )
        )
    return records, "available"


class ProcessExplorerBackend:
    def __init__(self, *, max_history: int = 5000) -> None:
        self.max_history = max(100, int(max_history))
        self.active: dict[int, ProcessRecord] = {}
        self.history: list[ProcessRecord] = []
        self.coverage = "not_started"

    def refresh(self, provider: Callable[[], tuple[list[ProcessRecord], str]] = collect_process_snapshot) -> list[ProcessRecord]:
        records, status = provider()
        self.coverage = f"polling:{status}"
        current_pids = {record.pid for record in records}
        for pid, existing in list(self.active.items()):
            if pid not in current_pids:
                existing.state = "exited"
                existing.event = "inferred_exit"
                existing.exited_at = _now()
                self._archive(existing)
                self.active.pop(pid, None)
        for record in records:
            existing = self.active.get(record.pid)
            if existing and existing.identity != record.identity:
                existing.state = "exited"
                existing.event = "pid_reused"
                existing.exited_at = record.observed_at
                self._archive(existing)
            self.active[record.pid] = record
        return list(self.active.values())

    def ingest_native(self, payload: dict[str, Any]) -> ProcessRecord | None:
        event = str(payload.get("event_type", "")).lower()
        aliases = {"process_started": "exec", "process_exec": "exec", "process_forked": "fork", "process_exited": "exit"}
        event = aliases.get(event, event)
        if event not in {"exec", "fork", "exit"}:
            return None
        try:
            pid = int(payload.get("pid"))
        except (TypeError, ValueError):
            return None
        timestamp = str(payload.get("timestamp") or _now())
        if event == "exit":
            record = self.active.pop(pid, None)
            if record is None:
                path = str(payload.get("path", payload.get("related_path", "")))
                record = ProcessRecord(process_identity(pid, timestamp, path), pid, payload.get("parent_pid"), payload.get("responsible_pid"), payload.get("uid"), str(payload.get("user", "")), str(payload.get("process_name", "")), path, [])
            record.state = "exited"
            record.event = "exit"
            record.exited_at = timestamp
            record.exit_status = payload.get("exit_status", payload.get("exit_code"))
            self._archive(record)
            self.coverage = "native_endpoint_security"
            return record
        path = str(payload.get("path", payload.get("related_path", "")))
        arguments = payload.get("process_arguments", payload.get("arguments", []))
        if not isinstance(arguments, list):
            arguments = []
        record = ProcessRecord(
            identity=process_identity(pid, timestamp, path),
            pid=pid,
            ppid=payload.get("parent_pid", payload.get("ppid")),
            responsible_pid=payload.get("responsible_pid", payload.get("rpid")),
            uid=payload.get("uid"),
            user=str(payload.get("user", payload.get("related_user", ""))),
            name=str(payload.get("process_name", "")) or path.rsplit("/", 1)[-1],
            path=path,
            arguments=[str(value)[:2048] for value in arguments[:64]],
            event=event,
            started_at=timestamp,
            observed_at=timestamp,
            architecture=str(payload.get("architecture", "unknown")),
            signing_id=str(payload.get("process_signing_id", payload.get("signing_id", ""))),
            team_id=str(payload.get("process_team_id", payload.get("team_id", ""))),
            platform_binary=bool(payload.get("process_platform_binary", payload.get("platform_binary", False))),
            code_signing_flags=payload.get("code_signing_flags", payload.get("cs_flags")),
            cdhash=str(payload.get("cdhash", "")),
            ancestry=[dict(value) for value in payload.get("process_ancestry", payload.get("ancestors", []))[:32] if isinstance(value, dict)],
            environment=redact_environment(payload.get("environment", {})) if isinstance(payload.get("environment", {}), dict) else {},
        )
        previous = self.active.get(pid)
        if previous and previous.identity != record.identity:
            previous.state = "exited"
            previous.event = "pid_reused"
            previous.exited_at = timestamp
            self._archive(previous)
        self.active[pid] = record
        self.coverage = "native_endpoint_security"
        return record

    def _archive(self, record: ProcessRecord) -> None:
        self.history.append(record)
        if len(self.history) > self.max_history:
            del self.history[: len(self.history) - self.max_history]
