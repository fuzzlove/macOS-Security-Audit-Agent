from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mac_audit_agent.rce_monitor.analyzer import RCEAnalyzer
from mac_audit_agent.rce_monitor.crash_diagnostics import MAX_CRASH_REPORT_BYTES, CrashDiagnosticCollector, classify_crash_diagnostic


def write_ips(path: Path, report: dict) -> bytes:
    raw = json.dumps({"app_name": report.get("procName", "Fixture")}).encode() + b"\n" + json.dumps(report).encode()
    path.write_bytes(raw)
    return raw


def test_memory_safety_ips_becomes_review_candidate_not_confirmed_rce(tmp_path: Path) -> None:
    path = tmp_path / "Fixture.ips"
    raw = write_ips(
        path,
        {
            "procName": "Fixture",
            "procPath": "/Applications/Fixture.app/Contents/MacOS/Fixture",
            "pid": 42,
            "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"},
            "termination": {"indicator": "Segmentation fault"},
            "incident": "fixture-incident",
        },
    )
    finding = classify_crash_diagnostic(path)
    assert finding is not None
    assert finding.artifact_sha256 == hashlib.sha256(raw).hexdigest()
    event = RCEAnalyzer().analyze(finding.telemetry)
    assert event is not None
    assert event.event_type != "CONFIRMED_REMOTE_CODE_EXECUTION"
    assert "RCE-MEMORY-SAFETY-001" in event.rule_ids
    assert "remote origin unknown" in finding.telemetry.metadata["telemetry_gaps"]


def test_non_memory_safety_ips_is_not_an_rce_candidate(tmp_path: Path) -> None:
    path = tmp_path / "NormalAbort.ips"
    write_ips(path, {"procName": "Fixture", "exception": {"type": "EXC_CRASH", "signal": "SIGABRT"}})
    assert classify_crash_diagnostic(path) is None


def test_crash_diagnostic_size_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "Huge.ips"
    path.write_bytes(b"x" * (MAX_CRASH_REPORT_BYTES + 1))
    with pytest.raises(ValueError, match="16 MiB"):
        classify_crash_diagnostic(path)


def test_collector_deduplicates_artifacts(tmp_path: Path) -> None:
    path = tmp_path / "Fixture.ips"
    write_ips(path, {"procName": "Fixture", "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"}})
    collector = CrashDiagnosticCollector([tmp_path])
    assert len(collector.collect_recent()) == 1
    assert collector.collect_recent() == []
