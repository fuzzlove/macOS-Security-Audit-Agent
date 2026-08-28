from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass


DEFAULT_WINDOWS = (5.0, 30.0, 300.0, 1800.0, 86400.0)


@dataclass(frozen=True)
class CorrelationEvent:
    monotonic_time: float
    process_key: str
    tree_key: str
    responsible_key: str
    directory_token: str
    volume_token: str
    signal_ids: tuple[str, ...]


@dataclass(frozen=True)
class WindowSummary:
    seconds: float
    event_count: int
    process_count: int
    directory_count: int
    volume_count: int
    signal_ids: tuple[str, ...]
    visibility_complete: bool


class MultiWindowCorrelator:
    """Monotonic, bounded correlation across process and process-tree keys."""

    def __init__(self, *, windows: tuple[float, ...] = DEFAULT_WINDOWS, max_keys: int = 2048, max_events_per_key: int = 4096) -> None:
        if not windows or any(value <= 0 for value in windows):
            raise ValueError("windows must contain positive durations")
        self.windows = tuple(sorted(set(windows)))
        self.max_keys = max(1, max_keys)
        self.max_events_per_key = max(1, max_events_per_key)
        self._events: OrderedDict[str, deque[CorrelationEvent]] = OrderedDict()
        self._incomplete_since: float | None = None
        self.evicted_keys = 0
        self.evicted_events = 0

    def add(self, event: CorrelationEvent) -> None:
        queue = self._events.setdefault(event.tree_key, deque())
        self._events.move_to_end(event.tree_key)
        queue.append(event)
        while len(queue) > self.max_events_per_key:
            queue.popleft(); self.evicted_events += 1
        cutoff = event.monotonic_time - self.windows[-1]
        while queue and queue[0].monotonic_time < cutoff:
            queue.popleft()
        while len(self._events) > self.max_keys:
            self._events.popitem(last=False); self.evicted_keys += 1

    def mark_sequence_gap(self, observed_monotonic: float) -> None:
        self._incomplete_since = observed_monotonic

    def mark_resynchronized(self) -> None:
        self._incomplete_since = None

    def summaries(self, tree_key: str, now_monotonic: float) -> tuple[WindowSummary, ...]:
        events = self._events.get(tree_key, ())
        result = []
        for seconds in self.windows:
            selected = [event for event in events if now_monotonic - event.monotonic_time <= seconds]
            result.append(WindowSummary(
                seconds=seconds,
                event_count=len(selected),
                process_count=len({event.process_key for event in selected}),
                directory_count=len({event.directory_token for event in selected}),
                volume_count=len({event.volume_token for event in selected}),
                signal_ids=tuple(sorted({signal for event in selected for signal in event.signal_ids})),
                visibility_complete=self._incomplete_since is None or now_monotonic - seconds > self._incomplete_since,
            ))
        return tuple(result)

    @property
    def retained_event_count(self) -> int:
        return sum(len(queue) for queue in self._events.values())
