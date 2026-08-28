from __future__ import annotations

import threading
import time
from pathlib import Path

from mac_audit_agent.anti_ransomware.degraded_observer import DegradedFilesystemObserver
from mac_audit_agent.anti_ransomware.multi_window import CorrelationEvent, MultiWindowCorrelator


def test_observer_has_no_construction_worker_and_detects_metadata(tmp_path: Path) -> None:
    before = {thread.ident for thread in threading.enumerate()}
    seen = []
    observer = DegradedFilesystemObserver(tmp_path, seen.append, interval_seconds=0.05, max_files=8, queue_size=4)
    assert {thread.ident for thread in threading.enumerate()} == before
    observer.start(); observer.start()
    fixture = tmp_path / "fixture.txt"
    fixture.write_text("safe synthetic content", encoding="utf-8")
    deadline = time.monotonic() + 2
    while not seen and time.monotonic() < deadline:
        time.sleep(0.02)
    assert seen and seen[0].operation == "created"
    assert Path(seen[0].path).is_relative_to(tmp_path)
    assert observer.stop() and not observer.running


def test_observer_ignores_symlink_escape_and_reports_scan_bound(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-ar-fixture"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "link").symlink_to(outside)
        observer = DegradedFilesystemObserver(tmp_path, lambda event: None, max_files=2)
        assert all(Path(path).is_relative_to(tmp_path) for path in observer._scan())
        (tmp_path / "a").write_text("a"); (tmp_path / "b").write_text("b")
        observer._scan()
        assert observer.scan_overflow
    finally:
        outside.unlink(missing_ok=True)


def test_multi_window_tree_correlation_is_bounded_and_gap_aware() -> None:
    correlator = MultiWindowCorrelator(windows=(5, 30), max_keys=2, max_events_per_key=3)
    for index in range(5):
        correlator.add(CorrelationEvent(float(index), f"p{index}", "tree", "responsible", f"d{index % 2}", f"v{index % 2}", ("encrypted_transition",)))
    summary_5, summary_30 = correlator.summaries("tree", 5.0)
    assert summary_5.event_count == 3 and summary_30.process_count == 3
    assert summary_30.directory_count == 2 and summary_30.volume_count == 2
    assert correlator.evicted_events == 2
    correlator.mark_sequence_gap(4.5)
    assert not correlator.summaries("tree", 5.0)[0].visibility_complete
    correlator.mark_resynchronized()
    assert correlator.summaries("tree", 5.0)[0].visibility_complete
    correlator.add(CorrelationEvent(6, "x", "tree2", "x", "d", "v", ()))
    correlator.add(CorrelationEvent(7, "x", "tree3", "x", "d", "v", ()))
    assert correlator.evicted_keys == 1
