from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock

from .models import ProcessIdentity


@dataclass(frozen=True)
class TreeActivity:
    root_key: str
    process_count: int
    qualifying_mutations: int
    triggered: bool


class ProcessTreeCorrelator:
    def __init__(self, *, threshold: int = 5, seconds: float = 30.0) -> None:
        self.threshold = threshold
        self.seconds = seconds
        self._parents: dict[str, str] = {}
        self._events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._lock = Lock()

    def register(self, process: ProcessIdentity, parent: ProcessIdentity | None = None) -> None:
        with self._lock:
            self._parents[process.stable_key] = parent.stable_key if parent else process.stable_key

    def root_for(self, process: ProcessIdentity) -> str:
        key = process.stable_key
        seen: set[str] = set()
        while key not in seen:
            seen.add(key)
            parent = self._parents.get(key, key)
            if parent == key:
                return key
            key = parent
        return process.stable_key

    def record(self, process: ProcessIdentity, timestamp: float, *, qualifies: bool) -> TreeActivity:
        with self._lock:
            root = self.root_for(process)
            events = self._events[root]
            while events and events[0][0] < timestamp - self.seconds:
                events.popleft()
            if qualifies:
                events.append((timestamp, process.stable_key))
            return TreeActivity(root, len({key for _, key in events}), len(events), len(events) >= self.threshold)
