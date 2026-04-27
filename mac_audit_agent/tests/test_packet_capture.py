from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.packet_capture import (
    MAX_CAPTURE_DURATION_SECONDS,
    PacketCaptureSession,
    build_tcpdump_command,
    sanitize_capture_filter,
    sanitize_interface_name,
    validate_capture_duration,
)


class FakeProcess:
    def __init__(self, *, returncode: int = 0, stderr: str = "", running: bool = False) -> None:
        self.returncode = None if running else returncode
        self.stderr = stderr
        self.pid = 1234
        self.terminated = False
        self.killed = False
        self.communicate_calls = 0

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        self.communicate_calls += 1
        if self.returncode is None:
            self.returncode = 0 if not self.killed else -9
        return ("", self.stderr)

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


def test_duration_capped_at_ten_minutes() -> None:
    assert validate_capture_duration(9999) == MAX_CAPTURE_DURATION_SECONDS


def test_custom_duration_must_be_positive_integer() -> None:
    with pytest.raises(ValueError):
        validate_capture_duration(0)


def test_interface_name_is_sanitized() -> None:
    assert sanitize_interface_name("en0") == "en0"
    with pytest.raises(ValueError):
        sanitize_interface_name("en0;rm -rf /")


def test_filter_input_is_sanitized() -> None:
    assert sanitize_capture_filter("tcp") == "tcp"
    assert sanitize_capture_filter("port 443") == "port 443"
    with pytest.raises(ValueError):
        sanitize_capture_filter("tcp and port 443")


def test_command_is_built_as_argv_list_not_shell_string(tmp_path: Path) -> None:
    command = build_tcpdump_command("en0", tmp_path / "capture.pcap", 60, "tcp")
    assert isinstance(command, list)
    assert command[:6] == ["/usr/sbin/tcpdump", "-i", "en0", "-w", str(tmp_path / "capture.pcap"), "-G"]


def test_shell_true_is_never_used(tmp_path: Path) -> None:
    captured = {}

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProcess(returncode=0)

    session = PacketCaptureSession(
        interface="en0",
        duration_seconds=30,
        capture_filter="tcp",
        evidence_dir=tmp_path,
        user_confirmed=True,
        popen_factory=fake_popen,
    )
    session.start()
    assert captured["kwargs"]["shell"] is False
    assert isinstance(captured["args"][0], list)


def test_metadata_json_is_written_and_sha256_calculated(tmp_path: Path) -> None:
    def fake_popen(*args, **kwargs):
        return FakeProcess(returncode=0)

    session = PacketCaptureSession(
        interface="en0",
        duration_seconds=30,
        capture_filter="tcp",
        evidence_dir=tmp_path,
        user_confirmed=True,
        popen_factory=fake_popen,
    )
    session.start()
    session.pcap_path.write_bytes(b"pcap-bytes")
    result = session.finish()
    metadata = json.loads(session.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pcap_sha256"] == result.metadata["pcap_sha256"]
    assert metadata["file_size_bytes"] == len(b"pcap-bytes")


def test_failed_tcpdump_creates_clear_error(tmp_path: Path) -> None:
    def fake_popen(*args, **kwargs):
        return FakeProcess(returncode=1, stderr="permission denied")

    session = PacketCaptureSession(
        interface="en0",
        duration_seconds=30,
        capture_filter="",
        evidence_dir=tmp_path,
        user_confirmed=True,
        popen_factory=fake_popen,
    )
    session.start()
    result = session.finish()
    assert result.metadata["status"] == "failed"
    assert "permission denied" in result.metadata["stderr_summary"]
    assert result.finding is not None


def test_cancel_stops_process(tmp_path: Path, monkeypatch) -> None:
    process = FakeProcess(running=True)

    def fake_popen(*args, **kwargs):
        return process

    session = PacketCaptureSession(
        interface="en0",
        duration_seconds=30,
        capture_filter="udp",
        evidence_dir=tmp_path,
        user_confirmed=True,
        popen_factory=fake_popen,
    )
    session.start()
    monkeypatch.setattr("mac_audit_agent.packet_capture.os.killpg", lambda pgid, sig: process.terminate())
    monkeypatch.setattr("mac_audit_agent.packet_capture.os.getpgid", lambda pid: pid)
    result = session.cancel()
    assert result.metadata["status"] == "cancelled"
    assert process.terminated or process.killed
