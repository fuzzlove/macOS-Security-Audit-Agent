from __future__ import annotations

import os
import json
import subprocess
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from mac_audit_agent.packet_capture import (
    MAX_CAPTURE_DURATION_SECONDS,
    PacketCaptureSession,
    assess_packet_capture_readiness,
    build_tcpdump_command,
    sanitize_capture_filter,
    sanitize_interface_name,
    validate_capture_duration,
)
from mac_audit_agent.ui.main_window import PacketCaptureProgressDialog


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
    assert sanitize_capture_filter("host 192.0.2.4 and tcp port 443") == "host 192.0.2.4 and tcp port 443"
    with pytest.raises(ValueError): sanitize_capture_filter("-i en1")
    with pytest.raises(ValueError): sanitize_capture_filter("tcp; whoami")


def test_readiness_checks_tool_permission_storage_and_interfaces(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.packet_capture.tcpdump_available", lambda: True)
    monkeypatch.setattr("mac_audit_agent.packet_capture.list_capture_interfaces", lambda: ["en0"])
    monkeypatch.setattr("mac_audit_agent.packet_capture.os.geteuid", lambda: 0)
    readiness = assess_packet_capture_readiness(tmp_path / "evidence")
    assert readiness.ready
    assert readiness.capture_permission_ready
    assert readiness.evidence_dir_writable


def test_capture_dependency_installer_uses_only_allowlisted_visible_homebrew_command(tmp_path: Path, monkeypatch):
    import mac_audit_agent.dependency_installer as installer

    brew = tmp_path / "brew"
    brew.write_text("#!/bin/sh\n", encoding="utf-8")
    brew.chmod(0o700)
    captured = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "opened", "")

    monkeypatch.setattr(installer, "HOMEBREW_PATHS", (brew,))
    result = installer.open_network_capture_install_in_terminal(str(brew), "wireshark-chmodbpf", runner=runner)
    assert result.status == "terminal_opened"
    assert "install --cask wireshark-chmodbpf" in captured["command"][2]
    assert captured["kwargs"]["shell"] is False
    with pytest.raises(ValueError):
        installer.open_network_capture_install_in_terminal(str(brew), "not-approved", runner=runner)


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


def test_seconds_remaining_uses_monotonic_deadline(tmp_path: Path, monkeypatch) -> None:
    now = {"value": 100.0}

    monkeypatch.setattr("mac_audit_agent.packet_capture.time.monotonic", lambda: now["value"])

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

    assert session.seconds_remaining() == 30
    now["value"] = 100.9
    assert session.seconds_remaining() == 29
    now["value"] = session._deadline_monotonic + 2.0
    assert session.seconds_remaining() == 0


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
    assert metadata["snapshot_length"] == 96
    assert session.pcap_path.with_suffix(".pcap.sha256").exists()
    assert session.metadata_path.with_suffix(".json.sha256").exists()


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


def test_progress_dialog_marks_complete_and_schedules_close(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    close_calls: list[int] = []

    class FakeResult:
        def __init__(self) -> None:
            self.metadata = {"status": "completed"}

    class FakeSession:
        duration_seconds = 5
        process = None

        def seconds_remaining(self) -> int:
            return 0

        def finish(self):
            return FakeResult()

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QTimer.singleShot", lambda delay, fn: (close_calls.append(delay), fn()))
    dialog = PacketCaptureProgressDialog(FakeSession())
    dialog._tick()

    assert dialog.status_label.text() == "Status: packet capture complete"
    assert dialog.countdown_label.text() == "Time remaining: 0s"
    assert dialog.result.metadata["status"] == "completed"
    assert close_calls == [750]
    dialog.close()
    app.processEvents()


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
