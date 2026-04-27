from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.models import RawLogEntry, utc_now_iso


MAX_CAPTURE_DURATION_SECONDS = 600
ALLOWED_CAPTURE_FILTERS = {"", "host 127.0.0.1", "tcp", "udp"}
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def list_capture_interfaces() -> list[str]:
    try:
        names = sorted({name for _index, name in socket.if_nameindex() if name})
    except OSError:
        names = []
    common = ["en0", "en1", "awdl0", "lo0"]
    for name in common:
        if name not in names:
            names.append(name)
    return names


def sanitize_interface_name(value: str) -> str:
    candidate = value.strip()
    if not candidate or not INTERFACE_PATTERN.fullmatch(candidate):
        raise ValueError("Interface name is invalid.")
    return candidate


def sanitize_capture_filter(value: str) -> str:
    candidate = " ".join(value.strip().split())
    if candidate in ALLOWED_CAPTURE_FILTERS:
        return candidate
    match = re.fullmatch(r"port\s+(\d{1,5})", candidate)
    if not match:
        raise ValueError("Capture filter is invalid.")
    port = int(match.group(1))
    if port < 1 or port > 65535:
        raise ValueError("Port filter must be between 1 and 65535.")
    return f"port {port}"


def validate_capture_duration(value: int) -> int:
    if value <= 0:
        raise ValueError("Capture duration must be a positive integer.")
    return min(value, MAX_CAPTURE_DURATION_SECONDS)


def default_evidence_dir(base_dir: Path | None = None) -> Path:
    root = base_dir or Path.cwd()
    return root / "evidence"


def packet_capture_output_paths(evidence_dir: Path, timestamp: str) -> tuple[Path, Path]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stem = f"packet_capture_{timestamp}"
    return evidence_dir / f"{stem}.pcap", evidence_dir / f"{stem}.json"


def build_tcpdump_command(interface: str, output_path: Path, duration_seconds: int, capture_filter: str = "") -> list[str]:
    command = [
        "/usr/sbin/tcpdump",
        "-i",
        sanitize_interface_name(interface),
        "-w",
        str(output_path),
        "-G",
        str(validate_capture_duration(duration_seconds)),
        "-W",
        "1",
    ]
    normalized_filter = sanitize_capture_filter(capture_filter)
    if normalized_filter:
        command.extend(normalized_filter.split(" "))
    return command


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class PacketCaptureResult:
    metadata: dict[str, Any]
    raw_logs: list[RawLogEntry]
    finding: dict[str, Any] | None = None
    manual_command: str = ""


class PacketCaptureSession:
    def __init__(
        self,
        *,
        interface: str,
        duration_seconds: int,
        capture_filter: str,
        evidence_dir: Path,
        user_confirmed: bool,
        popen_factory: Any = subprocess.Popen,
    ) -> None:
        self.interface = sanitize_interface_name(interface)
        self.duration_seconds = validate_capture_duration(duration_seconds)
        self.capture_filter = sanitize_capture_filter(capture_filter)
        self.evidence_dir = evidence_dir
        self.user_confirmed = user_confirmed
        self.popen_factory = popen_factory
        timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        self.capture_id = f"packet-capture-{timestamp}"
        self.pcap_path, self.metadata_path = packet_capture_output_paths(self.evidence_dir, timestamp)
        self.command = build_tcpdump_command(self.interface, self.pcap_path, self.duration_seconds, self.capture_filter)
        self.process: Any = None
        self.start_time = ""
        self.end_time = ""
        self.status = "waiting"
        self.stderr_text = ""
        self.exit_code: int | None = None

    def manual_command_preview(self) -> str:
        return " ".join(self.command)

    def start(self) -> None:
        self.start_time = utc_now_iso()
        self.status = "running"
        self.process = self.popen_factory(
            self.command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,
        )

    def finish(self, grace_seconds: float = 2.0) -> PacketCaptureResult:
        assert self.process is not None
        if self.process.poll() is None:
            try:
                _stdout, stderr = self.process.communicate(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                self._terminate_process(grace_seconds)
                _stdout, stderr = self.process.communicate(timeout=grace_seconds)
        else:
            _stdout, stderr = self.process.communicate(timeout=grace_seconds)
        self.end_time = utc_now_iso()
        self.stderr_text = (stderr or "").strip()
        self.exit_code = self.process.returncode
        if self.exit_code == 0 and self.pcap_path.exists():
            self.status = "completed"
        elif self.status != "cancelled":
            self.status = "failed"
        return self._result_from_state()

    def cancel(self, grace_seconds: float = 2.0) -> PacketCaptureResult:
        self.status = "cancelled"
        if self.process is not None and self.process.poll() is None:
            self._terminate_process(grace_seconds)
            try:
                _stdout, stderr = self.process.communicate(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                stderr = ""
            self.stderr_text = (stderr or "").strip()
            self.exit_code = self.process.returncode
        self.end_time = utc_now_iso()
        return self._result_from_state()

    def seconds_remaining(self) -> int:
        if not self.start_time:
            return self.duration_seconds
        started = self._parse_iso(self.start_time)
        remaining = self.duration_seconds - max(0, int(time.time() - started))
        return max(0, remaining)

    def _terminate_process(self, grace_seconds: float) -> None:
        assert self.process is not None
        if self.process.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        except OSError:
            self.process.terminate()
        deadline = time.time() + grace_seconds
        while time.time() < deadline:
            if self.process.poll() is not None:
                return
            time.sleep(0.05)
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        except OSError:
            self.process.kill()

    def _result_from_state(self) -> PacketCaptureResult:
        sha256 = ""
        file_size = 0
        if self.pcap_path.exists():
            try:
                sha256 = compute_sha256(self.pcap_path)
                file_size = self.pcap_path.stat().st_size
            except OSError:
                sha256 = ""
                file_size = 0
        metadata = {
            "capture_id": self.capture_id,
            "start_time": self.start_time,
            "end_time": self.end_time or utc_now_iso(),
            "duration_seconds": self.duration_seconds,
            "interface": self.interface,
            "filter": self.capture_filter,
            "pcap_path": str(self.pcap_path),
            "pcap_sha256": sha256,
            "file_size_bytes": file_size,
            "command_used": self.command,
            "exit_code": self.exit_code,
            "stderr_summary": self.stderr_text[:500],
            "user_confirmed": bool(self.user_confirmed),
            "status": self.status,
        }
        self.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        logs = [
            RawLogEntry("packet_capture", self.manual_command_preview(), self.start_time or utc_now_iso(), None, "", f"capture {self.status} started interface={self.interface}"),
            RawLogEntry("packet_capture", str(self.pcap_path), metadata["end_time"], self.exit_code, metadata["stderr_summary"], f"status={self.status} sha256={sha256 or 'unavailable'}"),
        ]
        finding = None
        if self.status != "completed":
            recommendation = (
                "Packet capture requires admin privileges on macOS. Re-run the app with appropriate permissions or run the displayed tcpdump command manually."
                if "permission denied" in self.stderr_text.lower()
                else "Review the tcpdump error, verify permissions and interface selection, and try again if capture is still needed."
            )
            finding = {
                "id": f"{self.capture_id}-failure",
                "category": "Packet Capture Snapshot",
                "title": "Packet Capture Snapshot failed" if self.status == "failed" else "Packet Capture Snapshot cancelled",
                "severity": "medium" if self.status == "failed" else "info",
                "description": "A user-requested packet capture snapshot did not complete successfully." if self.status == "failed" else "A user-requested packet capture snapshot was cancelled before completion.",
                "evidence": metadata["stderr_summary"] or self.manual_command_preview(),
                "command_used": self.manual_command_preview(),
                "remediation_suggestion": recommendation,
                "warning": "Packet captures can contain sensitive traffic metadata or contents. Review authorization and privacy boundaries before retrying.",
                "evidence_summary": f"status={self.status} interface={self.interface}",
                "raw_evidence_ref": self.capture_id,
                "why_this_matters": "Failure means the requested evidence was not collected. Cancellation may be intentional; permissions failures are common on macOS without admin access.",
                "false_positive_notes": "A cancelled or permission-denied capture is not a security finding by itself.",
                "recommended_next_steps": recommendation,
                "what_can_go_wrong": "Running packet capture without authorization can expose sensitive metadata or contents and may violate policy.",
                "remediation_steps": [recommendation],
                "remediation_commands": [self.manual_command_preview()],
                "remediation_risk": "sensitive",
                "requires_admin": "permission denied" in self.stderr_text.lower(),
                "reversible": True,
                "estimated_impact": "medium",
                "verification_steps": ["Confirm the pcap and metadata files were written locally if the capture is retried."],
                "remediation_references": ["tcpdump manual page: review local capture syntax and privileges before retrying."],
            }
        return PacketCaptureResult(metadata=metadata, raw_logs=logs, finding=finding, manual_command=self.manual_command_preview())

    def _parse_iso(self, value: str) -> float:
        try:
            return time.time() if not value else time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return time.time()


def tcpdump_available() -> bool:
    return Path("/usr/sbin/tcpdump").exists()
