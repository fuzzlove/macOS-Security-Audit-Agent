from __future__ import annotations

from dataclasses import dataclass
from queue import Empty, Full, PriorityQueue
from threading import Event, Lock, Thread
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


@dataclass(order=True, frozen=True)
class QueuedEvent(Generic[T]):
    priority: int
    sequence: int
    payload: T


class BoundedAnalysisService(Generic[T]):
    """One-owner bounded worker; importing or constructing starts no thread."""

    def __init__(self, handler: Callable[[T], None], *, max_queue: int = 1024) -> None:
        self._handler = handler
        self._queue: PriorityQueue[QueuedEvent[T]] = PriorityQueue(maxsize=max_queue)
        self._stop = Event()
        self._lock = Lock()
        self._worker: Thread | None = None
        self._generation = 0
        self.accepted = 0
        self.dropped = 0
        self.processed = 0

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def running(self) -> bool:
        return bool(self._worker and self._worker.is_alive())

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self._generation += 1
            self._worker = Thread(target=self._run, name="msaa-anti-ransomware-analysis", daemon=False)
            self._worker.start()
            return True

    def submit(self, payload: T, *, priority: int, sequence: int) -> bool:
        try:
            self._queue.put_nowait(QueuedEvent(priority, sequence, payload))
            self.accepted += 1
            return True
        except Full:
            self.dropped += 1
            return False

    def stop(self, timeout: float = 2.0) -> bool:
        self._stop.set()
        worker = self._worker
        if worker:
            worker.join(timeout=max(0.0, timeout))
        return not self.running

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                self._handler(item.payload)
                self.processed += 1
            finally:
                self._queue.task_done()
