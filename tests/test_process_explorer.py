from __future__ import annotations

from mac_audit_agent.process_explorer import ProcessExplorerBackend, ProcessRecord, collect_process_snapshot, process_identity, redact_environment


def _record(pid: int, started: str, path: str) -> ProcessRecord:
    return ProcessRecord(process_identity(pid, started, path), pid, 1, None, 501, "user", path.rsplit("/", 1)[-1], path, [path], started_at=started)


def test_native_exec_preserves_attribution_and_redacts_environment() -> None:
    backend = ProcessExplorerBackend()
    record = backend.ingest_native(
        {
            "event_type": "process_started",
            "pid": 42,
            "parent_pid": 10,
            "responsible_pid": 9,
            "timestamp": "2026-07-15T12:00:00+00:00",
            "path": "/tmp/example",
            "process_arguments": ["example", "--scan"],
            "process_ancestry": [{"pid": 10, "name": "shell"}],
            "process_signing_id": "com.example.tool",
            "environment": {"PATH": "/usr/bin", "API_TOKEN": "do-not-store"},
        }
    )

    assert record is not None
    assert record.responsible_pid == 9
    assert record.signing_id == "com.example.tool"
    assert record.environment["API_TOKEN"] == "[REDACTED]"
    assert record.environment["PATH"] == "/usr/bin"


def test_exit_archives_process_and_keeps_exit_status() -> None:
    backend = ProcessExplorerBackend()
    backend.ingest_native({"event_type": "process_exec", "pid": 5, "timestamp": "2026-07-15T12:00:00+00:00", "path": "/bin/tool"})
    exited = backend.ingest_native({"event_type": "process_exited", "pid": 5, "timestamp": "2026-07-15T12:01:00+00:00", "exit_status": 9})

    assert exited is not None
    assert exited.state == "exited"
    assert exited.exit_status == 9
    assert 5 not in backend.active
    assert backend.history[-1] is exited


def test_polling_detects_pid_reuse_by_start_identity() -> None:
    backend = ProcessExplorerBackend()
    first = _record(7, "2026-07-15T12:00:00+00:00", "/bin/first")
    second = _record(7, "2026-07-15T12:05:00+00:00", "/bin/second")

    backend.refresh(lambda: ([first], "available"))
    backend.refresh(lambda: ([second], "available"))

    assert backend.active[7].path == "/bin/second"
    assert backend.history[-1].event == "pid_reused"


def test_environment_redaction_is_bounded() -> None:
    payload = {f"KEY_{index}": "x" for index in range(100)}
    payload["PASSWORD"] = "secret"
    result = redact_environment(payload, limit=4)
    assert len(result) == 4


def test_polling_parser_keeps_start_identity_and_resource_usage() -> None:
    class Result:
        returncode = 0
        stderr = ""
        stdout = " 42 1 501 alice S 2.5 1.2 Tue Jul 15 12:30:00 2026 /Applications/Example.app/Contents/MacOS/Example\n"

    records, status = collect_process_snapshot(lambda *_args, **_kwargs: Result())

    assert status == "available"
    assert records[0].pid == 42
    assert records[0].cpu_percent == 2.5
    assert records[0].path.endswith("/Example")
