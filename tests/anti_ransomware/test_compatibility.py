from __future__ import annotations

import base64
import os
import threading
from pathlib import Path

from mac_audit_agent.anti_ransomware.behavior_windows import CompatibilityBurstWindow
from mac_audit_agent.anti_ransomware.compatibility_profile import classify_compatibility
from mac_audit_agent.anti_ransomware.file_statistics import analyze_bytes
from mac_audit_agent.anti_ransomware.models import FileMutation, ProcessIdentity
from mac_audit_agent.anti_ransomware.simulator import run_safe_simulation


def identity() -> ProcessIdentity:
    return ProcessIdentity(123, 7, "/tmp/synthetic", "a" * 64, 501, "boot-test")


def mutation(at: float, index: int) -> FileMutation:
    return FileMutation(str(index), at, identity(), f"path-{index}", "modified_close", analyze_bytes(os.urandom(4096)))


def test_import_starts_no_threads():
    before = {thread.ident for thread in threading.enumerate()}
    __import__("mac_audit_agent.anti_ransomware")
    assert {thread.ident for thread in threading.enumerate()} == before


def test_compatibility_size_image_and_gzip_exclusions():
    assert classify_compatibility(analyze_bytes(os.urandom(1023))).reason == "below_compatibility_minimum"
    large = analyze_bytes(os.urandom(4096), original_size=50 * 1024 * 1024 + 1)
    assert classify_compatibility(large).reason == "above_compatibility_maximum"
    assert classify_compatibility(analyze_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(4096))).reason == "recognized_image_header"
    assert classify_compatibility(analyze_bytes(b"\x1f\x8b" + os.urandom(4096))).reason == "gzip_header"


def test_random_and_base64_encrypted_looking_outputs():
    random_result = classify_compatibility(analyze_bytes(os.urandom(256 * 1024)))
    assert random_result.qualifies, random_result
    encoded = base64.b64encode(os.urandom(64 * 1024))
    base64_result = classify_compatibility(analyze_bytes(encoded))
    assert base64_result.qualifies, base64_result


def test_five_in_thirty_triggers_and_old_events_expire():
    window = CompatibilityBurstWindow()
    for index in range(4):
        assert not window.record(mutation(float(index), index), qualifies=True).triggered
    assert window.record(mutation(4.0, 4), qualifies=True).triggered
    result = window.record(mutation(35.0, 5), qualifies=True)
    assert not result.triggered
    assert result.qualifying_count == 1


def test_safe_simulator_is_bounded_and_cleans_up():
    report = run_safe_simulation(file_count=5, bytes_per_file=2048)
    assert report["simulation"] is True
    assert len(report["files"]) == 5
    assert all(item["size"] == 2048 for item in report["files"])
    assert len(report["report_sha256"]) == 64
