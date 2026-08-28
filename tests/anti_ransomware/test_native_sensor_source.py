from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native" / "anti_ransomware_sensor"


def test_native_sensor_uses_bounded_owned_message_lifecycle():
    source = (NATIVE / "main.c").read_text(encoding="utf-8")
    assert "es_retain_message(message)" in source
    assert "es_release_message(message)" in source
    assert "msaa_ar_queue_init(&message_queue, 4096)" in source
    assert "dispatch_queue_create" in source and "dispatch_async" in source


@pytest.mark.skipif(platform.system() != "Darwin" or shutil.which("xcrun") is None, reason="macOS Command Line Tools required")
def test_native_sensor_core_compiles_and_runs():
    result = subprocess.run(["sh", str(NATIVE / "test.sh")], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "all tests passed" in result.stdout
    assert "containment_boundary: identity, pause, resume, terminate, critical refusal passed" in result.stdout
    assert "containment_watchdog: bounded expiry rollback passed" in result.stdout


def test_native_containment_has_no_arbitrary_cli_and_revalidates_before_signal():
    source = (NATIVE / "containment_boundary.c").read_text(encoding="utf-8")
    fixture = (NATIVE / "Tests/containment_fixture_test.c").read_text(encoding="utf-8")
    assert "msaa_ar_revalidate_process_identity(expected)" in source
    assert "PROC_PIDTBSDINFO" in source and "proc_pidpath" in source
    assert "executable_sha256" in source and "st_ino" in source and "pbi_start_tvsec" in source
    assert "SSTOP" in source and "SZOMB" in source
    assert "argc != 2" in fixture and '"--self-test"' in fixture
