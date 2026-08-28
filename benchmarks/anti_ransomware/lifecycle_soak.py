from __future__ import annotations

import argparse
import json
import os
import resource
import tempfile
import threading
import time
from pathlib import Path

from mac_audit_agent.anti_ransomware.degraded_observer import DegradedFilesystemObserver


def descriptor_count() -> int | None:
    try:
        return len(os.listdir("/dev/fd"))
    except OSError:
        return None


def run(duration: float) -> dict:
    start_threads = threading.active_count(); start_fds = descriptor_count()
    started = time.monotonic(); seen = []
    with tempfile.TemporaryDirectory(prefix="msaa-ar-soak-") as directory:
        root = Path(directory)
        observer = DegradedFilesystemObserver(root, seen.append, interval_seconds=0.05, max_files=256, queue_size=64)
        observer.start()
        index = 0
        while time.monotonic() - started < duration:
            fixture = root / f"fixture-{index % 32}.txt"
            fixture.write_text(f"synthetic-{index}", encoding="utf-8")
            index += 1
            time.sleep(0.01)
        shutdown_started = time.monotonic()
        stopped = observer.stop(timeout=2.0)
        shutdown_seconds = time.monotonic() - shutdown_started
        result = {
            "schema_version": "1.0", "workload": "degraded_metadata_observer",
            "duration_seconds": time.monotonic() - started, "writes": index,
            "events_delivered": len(seen), "dropped_events": observer.dropped_events,
            "scan_overflow": observer.scan_overflow, "shutdown_seconds": shutdown_seconds,
            "shutdown_complete": stopped, "threads_start": start_threads,
            "threads_end": threading.active_count(), "fds_start": start_fds,
            "fds_end": descriptor_count(), "max_rss_bytes_raw": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "qualification": "CHARACTERIZATION_ONLY_UNAPPROVED_BUDGET",
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--seconds", type=float, default=5.0); parser.add_argument("--output", type=Path)
    args = parser.parse_args(); result = run(max(1.0, args.seconds)); encoded = json.dumps(result, sort_keys=True, indent=2)
    if args.output: args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
