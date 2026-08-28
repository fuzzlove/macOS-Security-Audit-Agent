from __future__ import annotations

import concurrent.futures
import heapq
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.performance.resource_budget import ResourceBudget, load_resource_budget
from mac_audit_agent.compat.enum import StrEnum


class TaskPriority(IntEnum):
    critical_user_action = 0
    user_action = 10
    background_high = 30
    background_normal = 50
    background_low = 80


class TaskStatus(StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"
    skipped_deduped = "skipped_deduped"
    skipped_cooldown = "skipped_cooldown"


@dataclass
class CancellationToken:
    _cancelled: bool = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled


@dataclass
class ScheduledTask:
    task_type: str
    subsystem: str
    callable: Callable[[CancellationToken], Any]
    priority: str = "background_normal"
    dedupe_key: str = ""
    timeout_seconds: int = 60
    resource_estimate: dict[str, Any] = field(default_factory=dict)
    task_id: str = field(default_factory=lambda: f"task-{uuid4()}")
    created_at: str = field(default_factory=utc_now_iso)
    started_at: str = ""
    completed_at: str = ""
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)
    status: str = TaskStatus.queued.value
    error: str = ""
    result: Any = None


class WorkScheduler:
    def __init__(self, budget: ResourceBudget | None = None, *, max_task_history: int = 500) -> None:
        self.budget = budget or load_resource_budget()
        self._lock = threading.RLock()
        self._queue: list[tuple[int, float, str]] = []
        self._tasks: dict[str, ScheduledTask] = {}
        self._running_by_dedupe: dict[str, str] = {}
        self._last_started_by_dedupe: dict[str, float] = {}
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, self.budget.max_concurrent_tasks), thread_name_prefix="msaa-worker")
        self._active_futures: dict[str, concurrent.futures.Future] = {}
        self._shutdown = False
        self._max_task_history = max(50, int(max_task_history))

    def schedule(self, task: ScheduledTask, *, cooldown_seconds: int = 0) -> ScheduledTask:
        now = time.monotonic()
        with self._lock:
            if self._shutdown:
                task.status = TaskStatus.cancelled.value
                task.error = "scheduler is shutting down"
                task.completed_at = utc_now_iso()
                return task
            if task.dedupe_key and task.dedupe_key in self._running_by_dedupe:
                task.status = TaskStatus.skipped_deduped.value
                return task
            if task.dedupe_key and cooldown_seconds > 0:
                last = self._last_started_by_dedupe.get(task.dedupe_key, 0)
                if now - last < cooldown_seconds:
                    task.status = TaskStatus.skipped_cooldown.value
                    return task
            self._tasks[task.task_id] = task
            priority = int(TaskPriority[task.priority]) if task.priority in TaskPriority.__members__ else int(TaskPriority.background_normal)
            heapq.heappush(self._queue, (priority, now, task.task_id))
        self._drain()
        return task

    def _drain(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            while self._queue and len(self._active_futures) < self.budget.max_concurrent_tasks:
                _priority, _created, task_id = heapq.heappop(self._queue)
                task = self._tasks[task_id]
                if task.cancellation_token.cancelled:
                    task.status = TaskStatus.cancelled.value
                    task.completed_at = utc_now_iso()
                    continue
                task.status = TaskStatus.running.value
                task.started_at = utc_now_iso()
                if task.dedupe_key:
                    self._running_by_dedupe[task.dedupe_key] = task.task_id
                    self._last_started_by_dedupe[task.dedupe_key] = time.monotonic()
                future = self._executor.submit(self._run_task, task)
                self._active_futures[task_id] = future
                future.add_done_callback(lambda _future, tid=task_id: self._complete(tid))

    def _run_task(self, task: ScheduledTask) -> Any:
        if task.cancellation_token.cancelled:
            task.status = TaskStatus.cancelled.value
            return None
        return task.callable(task.cancellation_token)

    def _complete(self, task_id: str) -> None:
        with self._lock:
            future = self._active_futures.pop(task_id, None)
            task = self._tasks.get(task_id)
            if task is None:
                return
            try:
                task.result = future.result(timeout=0) if future is not None else None
                if task.status != TaskStatus.cancelled.value:
                    task.status = TaskStatus.succeeded.value
            except Exception as exc:
                task.error = str(exc)
                task.status = TaskStatus.failed.value
            task.completed_at = utc_now_iso()
            if task.dedupe_key and self._running_by_dedupe.get(task.dedupe_key) == task_id:
                self._running_by_dedupe.pop(task.dedupe_key, None)
            completed_ids = [identifier for identifier, item in self._tasks.items()
                             if item.status in {TaskStatus.succeeded.value, TaskStatus.failed.value,
                                                TaskStatus.cancelled.value, TaskStatus.skipped_deduped.value,
                                                TaskStatus.skipped_cooldown.value}]
            for identifier in completed_ids[:-self._max_task_history]:
                self._tasks.pop(identifier, None)
        self._drain()

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return False
            task.cancellation_token.cancel()
            future = self._active_futures.get(task_id)
            if future is not None:
                future.cancel()
            task.status = TaskStatus.cancelled.value
            return True

    def cancel_background_tasks(self) -> int:
        count = 0
        with self._lock:
            for task in self._tasks.values():
                if task.priority.startswith("background") and task.status in {TaskStatus.queued.value, TaskStatus.running.value}:
                    task.cancellation_token.cancel()
                    task.status = TaskStatus.cancelled.value
                    count += 1
        return count

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            tasks = [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "subsystem": task.subsystem,
                    "priority": task.priority,
                    "dedupe_key": task.dedupe_key,
                    "status": task.status,
                    "created_at": task.created_at,
                    "started_at": task.started_at,
                    "completed_at": task.completed_at,
                    "error": task.error,
                }
                for task in self._tasks.values()
            ]
            return {
                "budget": self.budget.to_dict(),
                "queued": len(self._queue),
                "running": len(self._active_futures),
                "tasks": tasks[-100:],
            }

    def shutdown(self, *, cancel: bool = True, timeout_seconds: float = 2.0) -> dict[str, int]:
        with self._lock:
            if self._shutdown:
                return {"cancelled": 0, "completed": 0, "still_running": len(self._active_futures)}
            self._shutdown = True
            tasks = list(self._tasks.values())
            futures = list(self._active_futures.values())
            self._queue.clear()
            cancelled = 0
            if cancel:
                for task in tasks:
                    if task.status in {TaskStatus.queued.value, TaskStatus.running.value}:
                        task.cancellation_token.cancel()
                        task.status = TaskStatus.cancelled.value
                        task.completed_at = utc_now_iso()
                        cancelled += 1
                for future in futures:
                    future.cancel()
        completed = 0
        still_running = 0
        if futures:
            done, pending = concurrent.futures.wait(futures, timeout=max(0.0, timeout_seconds))
            completed = len(done)
            still_running = len(pending)
        self._executor.shutdown(wait=not still_running, cancel_futures=True)
        return {"cancelled": cancelled, "completed": completed, "still_running": still_running}


_GLOBAL_SCHEDULER: WorkScheduler | None = None


def get_global_scheduler(budget: ResourceBudget | None = None) -> WorkScheduler:
    global _GLOBAL_SCHEDULER
    if _GLOBAL_SCHEDULER is None or _GLOBAL_SCHEDULER._shutdown:
        _GLOBAL_SCHEDULER = WorkScheduler(budget)
    return _GLOBAL_SCHEDULER
