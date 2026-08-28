"""Bounded, debounced metadata-only file activity monitor."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from time import monotonic


@dataclass(frozen=True)
class FileActivity:
    operation: str
    path_token: str
    pid: int
    timestamp: float


class FileActivityMonitor:
    def __init__(self, *, max_events: int = 4096, debounce_seconds: float = 0.05) -> None:
        self.events = deque(maxlen=max_events)
        self.debounce_seconds = debounce_seconds
        self.dropped = 0
        self._last: dict[tuple[str, str, int], float] = {}

    def record(self, operation: str, path_token: str, pid: int, timestamp: float | None = None) -> bool:
        now = monotonic() if timestamp is None else timestamp
        key = operation, path_token, pid
        if now - self._last.get(key, float("-inf")) < self.debounce_seconds:
            self.dropped += 1
            return False
        self._last[key] = now
        self.events.append(FileActivity(operation, path_token, pid, now))
        return True

    def drain(self, limit: int = 256) -> list[FileActivity]:
        return [self.events.popleft() for _ in range(min(limit, len(self.events)))]


__all__ = ["FileActivity", "FileActivityMonitor"]
