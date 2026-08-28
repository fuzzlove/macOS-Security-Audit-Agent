from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Callable


@dataclass(frozen=True)
class DegradedFileEvent:
    path: str
    operation: str
    observed_monotonic: float
    size: int
    mtime_ns: int


class DegradedFilesystemObserver:
    """Bounded metadata observer for explicit development scopes.

    This is delayed observation with no reliable process attribution and no
    preemptive authorization. Construction performs no I/O and starts no worker.
    """

    def __init__(
        self,
        root: Path,
        callback: Callable[[DegradedFileEvent], None],
        *,
        interval_seconds: float = 0.25,
        max_files: int = 10_000,
        queue_size: int = 1_024,
    ) -> None:
        self.root = Path(root).resolve()
        self.callback = callback
        self.interval_seconds = max(0.05, interval_seconds)
        self.max_files = max(1, max_files)
        self._events: Queue[DegradedFileEvent] = Queue(maxsize=max(1, queue_size))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, tuple[int, int]] = {}
        self.dropped_events = 0
        self.scan_overflow = False

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        if not self.root.is_dir():
            raise ValueError("degraded observation root must be an existing directory")
        self._snapshot = self._scan()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="MSAAARDegradedObserver", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> bool:
        self._stop.set()
        thread = self._thread
        if thread:
            thread.join(timeout)
        self._thread = None if not thread or not thread.is_alive() else thread
        return not self.running

    def poll_once(self) -> list[DegradedFileEvent]:
        current = self._scan()
        now = time.monotonic()
        events: list[DegradedFileEvent] = []
        for path, state in current.items():
            old = self._snapshot.get(path)
            if old != state:
                events.append(DegradedFileEvent(path, "created" if old is None else "modified", now, state[0], state[1]))
        for path, old in self._snapshot.items():
            if path not in current:
                events.append(DegradedFileEvent(path, "deleted", now, old[0], old[1]))
        self._snapshot = current
        return events

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            for event in self.poll_once():
                try:
                    self._events.put_nowait(event)
                except Full:
                    self.dropped_events += 1
            while not self._stop.is_set():
                try:
                    event = self._events.get_nowait()
                except Empty:
                    break
                try:
                    self.callback(event)
                finally:
                    self._events.task_done()

    def _scan(self) -> dict[str, tuple[int, int]]:
        snapshot: dict[str, tuple[int, int]] = {}
        self.scan_overflow = False
        for directory, names, files in os.walk(self.root, followlinks=False):
            names[:] = [name for name in names if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                if path.is_symlink():
                    continue
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(self.root)
                    stat = resolved.stat()
                except (OSError, ValueError):
                    continue
                snapshot[str(resolved)] = (stat.st_size, stat.st_mtime_ns)
                if len(snapshot) >= self.max_files:
                    self.scan_overflow = True
                    return snapshot
        return snapshot
