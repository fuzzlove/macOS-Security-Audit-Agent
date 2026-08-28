from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import TelemetryEvent

MAX_CRASH_REPORT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class CrashDiagnosticFinding:
    telemetry: TelemetryEvent
    artifact_sha256: str
    artifact_size: int


def _load_ips(path: Path) -> tuple[dict[str, Any], bytes]:
    size = path.stat().st_size
    if size <= 0 or size > MAX_CRASH_REPORT_BYTES:
        raise ValueError("crash diagnostic is empty or exceeds the 16 MiB evidence limit")
    raw = path.read_bytes()
    first, separator, remainder = raw.partition(b"\n")
    try:
        header = json.loads(first.decode("utf-8"))
        report = json.loads(remainder.decode("utf-8")) if separator and remainder.strip() else header
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("crash diagnostic is not a supported bounded IPS JSON report") from exc
    if not isinstance(header, dict) or not isinstance(report, dict):
        raise ValueError("crash diagnostic JSON root must be an object")
    return {**header, **report}, raw


def classify_crash_diagnostic(path: Path) -> CrashDiagnosticFinding | None:
    """Classify Apple IPS evidence as a memory-safety candidate, never as proof of RCE."""
    payload, raw = _load_ips(path)
    exception = payload.get("exception") if isinstance(payload.get("exception"), dict) else {}
    termination = payload.get("termination") if isinstance(payload.get("termination"), dict) else {}
    asi = payload.get("asi") if isinstance(payload.get("asi"), dict) else {}
    diagnostic_text = " ".join(
        [
            str(exception.get("type", "")),
            str(exception.get("subtype", "")),
            str(exception.get("signal", "")),
            str(termination.get("indicator", "")),
            str(payload.get("vmRegionInfo", "")),
            json.dumps(asi, sort_keys=True)[:8192],
        ]
    ).lower()
    markers = {
        "exc_bad_access": "invalid memory access",
        "sigsegv": "segmentation fault",
        "sigbus": "bus error",
        "sigill": "illegal instruction",
        "stack buffer overflow": "stack buffer overflow diagnostic",
        "stack smashing": "stack protection failure",
        "stack overflow": "stack overflow diagnostic",
        "stack exhaustion": "stack exhaustion diagnostic",
        "guard page": "guard page violation",
        "invalid return address": "invalid return address",
        "heap corruption": "heap corruption diagnostic",
        "double free": "double free diagnostic",
        "invalid free": "invalid free diagnostic",
        "use-after-free": "use-after-free diagnostic",
        "use after free": "use-after-free diagnostic",
        "wild pointer": "wild pointer diagnostic",
        "zone corruption": "allocator zone corruption diagnostic",
        "out-of-bounds": "out-of-bounds memory access",
        "out of bounds": "out-of-bounds memory access",
        "buffer overflow detected": "buffer overflow runtime diagnostic",
        "guard malloc": "guard allocator diagnostic",
        "malloc error": "allocator integrity diagnostic",
    }
    signals = sorted({description for marker, description in markers.items() if marker in diagnostic_text})
    if not signals:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    process_name = str(payload.get("procName") or payload.get("app_name") or "unknown")
    process_path = str(payload.get("procPath") or "")
    observed_at = str(payload.get("captureTime") or payload.get("timestamp") or datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="microseconds"))
    faulting_thread_index = payload.get("faultingThread")
    threads = payload.get("threads") if isinstance(payload.get("threads"), list) else []
    faulting_thread: dict[str, Any] = {}
    if isinstance(faulting_thread_index, int) and 0 <= faulting_thread_index < len(threads) and isinstance(threads[faulting_thread_index], dict):
        faulting_thread = threads[faulting_thread_index]
    thread_state = faulting_thread.get("threadState") if isinstance(faulting_thread.get("threadState"), dict) else {}
    registers: dict[str, Any] = {}
    for key, value in list(thread_state.items())[:64]:
        if isinstance(value, (str, int, float, bool)):
            registers[str(key)[:64]] = value
        elif isinstance(value, dict) and isinstance(value.get("value"), (str, int, float)):
            registers[str(key)[:64]] = value.get("value")
    fault_address = exception.get("faultAddress") or exception.get("address") or payload.get("faultAddress")
    instruction_pointer = thread_state.get("pc") or thread_state.get("rip") or thread_state.get("pcValue")
    stack_pointer = thread_state.get("sp") or thread_state.get("rsp") or thread_state.get("spValue")
    stack_corruption = any(token in diagnostic_text for token in ("stack buffer overflow", "stack smashing", "stack overflow", "stack exhaustion", "stack guard", "invalid return address"))
    heap_corruption = any(token in diagnostic_text for token in ("heap corruption", "double free", "invalid free", "use-after-free", "use after free", "wild pointer", "zone corruption", "malloc error"))
    buffer_overflow = "buffer overflow" in diagnostic_text
    telemetry = TelemetryEvent(
        kind="memory_safety_crash",
        observed_at=observed_at,
        sensor="apple_crash_diagnostics",
        process={
            "name": process_name,
            "executable": process_path,
            "pid": payload.get("pid") if isinstance(payload.get("pid"), int) else None,
            "architecture": payload.get("cpuType", ""),
        },
        memory_context={
            "memory_safety_crash": True,
            "crash_signals": signals,
            "exception_type": str(exception.get("type", "")),
            "exception_subtype": str(exception.get("subtype", "")),
            "exception_signal": str(exception.get("signal", "")),
            "fault_address": fault_address,
            "instruction_pointer": instruction_pointer,
            "stack_pointer": stack_pointer,
            "thread_id": faulting_thread.get("id") or faulting_thread_index,
            "faulting_thread": faulting_thread_index,
            "registers": registers,
            "stack_corruption": stack_corruption,
            "stack_overflow": "stack overflow" in diagnostic_text or "stack exhaustion" in diagnostic_text,
            "heap_corruption": heap_corruption,
            "use_after_free": "use-after-free" in diagnostic_text or "use after free" in diagnostic_text,
            "out_of_bounds": "out-of-bounds" in diagnostic_text or "out of bounds" in diagnostic_text,
            "buffer_overflow": buffer_overflow,
            "control_flow_anomaly": any(token in diagnostic_text for token in ("invalid return address", "unexpected instruction pointer", "sigill")),
            "crash_signature": str(payload.get("incident", "")) or digest[:32],
        },
        metadata={
            "sensor_health": "diagnostic_artifact",
            "artifact_sha256": digest,
            "artifact_size": len(raw),
            "incident_id": str(payload.get("incident", "")),
            "claim_boundary": "crash evidence can indicate a memory-safety defect; it does not prove exploitation or remote code execution",
            "telemetry_gaps": ["triggering input unavailable", "exploitability unknown", "remote origin unknown"],
        },
        raw_reference=str(path),
    )
    return CrashDiagnosticFinding(telemetry=telemetry, artifact_sha256=digest, artifact_size=len(raw))


__all__ = ["CrashDiagnosticFinding", "MAX_CRASH_REPORT_BYTES", "classify_crash_diagnostic"]


class CrashDiagnosticCollector:
    """Bounded, read-only collector for recently created Apple IPS reports."""

    def __init__(self, roots: list[Path] | None = None) -> None:
        self.roots = roots or [Path("/Library/Logs/DiagnosticReports")]
        self.seen: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._seen_limit = 4096

    def collect_recent(self, *, maximum_files: int = 32, maximum_age_seconds: int = 900) -> list[CrashDiagnosticFinding]:
        cutoff = time.time() - max(60, maximum_age_seconds)
        candidates: list[Path] = []
        for root in self.roots[:32]:
            try:
                candidates.extend(item for item in root.glob("*.ips") if item.is_file() and item.stat().st_mtime >= cutoff)
            except OSError:
                continue
        findings: list[CrashDiagnosticFinding] = []
        for path in sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True)[: max(1, min(maximum_files, 128))]:
            try:
                finding = classify_crash_diagnostic(path)
            except (OSError, ValueError):
                continue
            if finding is None or finding.artifact_sha256 in self.seen:
                continue
            if len(self._seen_order) >= self._seen_limit:
                self.seen.discard(self._seen_order.popleft())
            self.seen.add(finding.artifact_sha256)
            self._seen_order.append(finding.artifact_sha256)
            findings.append(finding)
        return findings


__all__.append("CrashDiagnosticCollector")
