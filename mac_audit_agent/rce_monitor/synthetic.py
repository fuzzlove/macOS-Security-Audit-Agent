from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import TelemetryEvent


def suspected_rce_demo(start: datetime | None = None) -> list[TelemetryEvent]:
    """Benign deterministic telemetry fixture; it executes no payload or command."""
    anchor = start or datetime(2026, 1, 15, 11, 5, tzinfo=timezone.utc)

    def observed(offset: float) -> str:
        return (anchor + timedelta(seconds=offset)).isoformat(timespec="milliseconds")

    common_user = {"uid": 501, "user_ref": "fixture-user", "session": "fixture-session"}
    parser = {"pid": 420, "executable": "/Applications/ExampleParser.app/Contents/MacOS/ExampleParser", "sha256": "A" * 64, "signing_status": "developer_id", "team_id": "FIXTURETEAM"}
    shell = {"pid": 421, "ppid": 420, "executable": "/bin/sh", "signing_status": "apple", "interactive": False, "tty": ""}
    drop = {"pid": 422, "ppid": 421, "executable": "/private/tmp/msaa-benign-fixture", "sha256": "B" * 64, "signing_status": "unsigned"}
    ancestry = (parser, shell)
    coverage = {"Process telemetry": "AVAILABLE", "File telemetry": "AVAILABLE", "Network telemetry": "AVAILABLE", "Memory telemetry": "LIMITED", "Crash telemetry": "AVAILABLE", "EndpointSecurity sensor": "AVAILABLE"}
    return [
        TelemetryEvent(kind="memory_safety_crash", observed_at=observed(0), sensor="synthetic_rce_fixture", process=parser, user_context=common_user, memory_context={"memory_safety_crash": True, "invalid_memory_access": True, "exception_type": "EXC_BAD_ACCESS", "exception_signal": "SIGSEGV", "fault_address": "0x0000000000000010", "thread_id": 7, "crash_signature": "fixture-parser-bad-access"}, metadata={"sensor_health": "fixture", "sensor_coverage": coverage}, raw_reference="fixture:rce:crash"),
        TelemetryEvent(kind="process_start", observed_at=observed(1), sensor="synthetic_rce_fixture", process=shell, parent_process=parser, process_ancestry=(parser,), user_context=common_user, metadata={"sensor_health": "fixture", "sensor_coverage": coverage}, raw_reference="fixture:rce:shell"),
        TelemetryEvent(kind="file_event", observed_at=observed(2), sensor="synthetic_rce_fixture", process=shell, parent_process=parser, process_ancestry=(parser,), user_context=common_user, file_context={"path": "/private/tmp/msaa-benign-fixture", "action": "created", "executable": True}, metadata={"sensor_health": "fixture", "sensor_coverage": coverage}, raw_reference="fixture:rce:file"),
        TelemetryEvent(kind="execution", observed_at=observed(3), sensor="synthetic_rce_fixture", process=drop, parent_process=shell, process_ancestry=ancestry, user_context=common_user, file_context={"path": "/private/tmp/msaa-benign-fixture", "action": "executed", "executable": True}, metadata={"sensor_health": "fixture", "sensor_coverage": coverage}, raw_reference="fixture:rce:execution"),
        TelemetryEvent(kind="network_connection", observed_at=observed(4), sensor="synthetic_rce_fixture", process=drop, parent_process=shell, process_ancestry=ancestry, user_context=common_user, network_context={"unexpected_outbound": True, "local_address": "192.0.2.10", "local_port": 49152, "remote_address": "203.0.113.20", "remote_port": 443, "protocol": "tcp", "dns_name": "fixture.invalid"}, metadata={"sensor_health": "fixture", "sensor_coverage": coverage}, raw_reference="fixture:rce:network"),
    ]


__all__ = ["suspected_rce_demo"]
