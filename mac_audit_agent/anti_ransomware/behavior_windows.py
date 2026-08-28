from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock

from .models import FileMutation


@dataclass(frozen=True)
class WindowResult:
    triggered: bool
    qualifying_count: int
    window_seconds: float
    process_key: str


class CompatibilityBurstWindow:
    def __init__(self, *, threshold: int = 5, seconds: float = 30.0) -> None:
        self.threshold = threshold
        self.seconds = seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def record(self, mutation: FileMutation, *, qualifies: bool) -> WindowResult:
        key = mutation.process.stable_key
        with self._lock:
            events = self._events[key]
            cutoff = mutation.timestamp - self.seconds
            while events and events[0] < cutoff:
                events.popleft()
            if qualifies:
                events.append(mutation.timestamp)
            return WindowResult(len(events) >= self.threshold, len(events), self.seconds, key)
