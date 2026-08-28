from __future__ import annotations

import time
import threading

from mac_audit_agent.cache.cache_manager import CacheManager
from mac_audit_agent.performance.api_refresh_manager import ApiRefreshManager
from mac_audit_agent.performance.memory import cap_text_output
from mac_audit_agent.performance.resource_budget import BALANCED_BUDGET, budget_for_profile
from mac_audit_agent.performance.subprocess_runner import run_bounded_command
from mac_audit_agent.performance.work_scheduler import ScheduledTask, WorkScheduler
from mac_audit_agent.runtime.platform_profile import detect_platform_profile
from mac_audit_agent.runtime.python_compat import current_python_gui_compatibility
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.app_shutdown import AppShutdownCoordinator


def test_resource_budget_profiles_are_bounded() -> None:
    assert budget_for_profile("low_resource").max_concurrent_tasks == 1
    assert budget_for_profile("balanced").max_api_requests_per_minute == 30
    assert budget_for_profile("thorough").max_subprocesses == 3


def test_scheduler_dedupes_running_task() -> None:
    scheduler = WorkScheduler(BALANCED_BUDGET)
    try:
        task = ScheduledTask(task_type="slow", subsystem="test", dedupe_key="same", callable=lambda token: time.sleep(0.1))
        scheduler.schedule(task)
        duplicate = scheduler.schedule(ScheduledTask(task_type="slow", subsystem="test", dedupe_key="same", callable=lambda token: None))
        assert duplicate.status in {"skipped_deduped", "queued"}
    finally:
        scheduler.shutdown(cancel=True)


def test_api_refresh_uses_cache_without_crash() -> None:
    cache = {"source": {"payload": {"ok": True}, "_cache_age_seconds": 0}}
    manager = ApiRefreshManager(BALANCED_BUDGET, cache_get=lambda key: cache.get(key), cache_set=lambda key, value: cache.__setitem__(key, value))
    result = manager.refresh("source", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert result.used_cache is True
    assert result.status == "cache_fresh"


def test_corrupt_cache_degrades_gracefully(tmp_path) -> None:
    cache = CacheManager(tmp_path)
    cache._path_for_key("broken").write_text("{broken", encoding="utf-8")
    result = cache.read_json("broken")
    assert result.corrupted is True


def test_bounded_subprocess_caps_output() -> None:
    result = run_bounded_command(["/bin/echo", "abcdef"], timeout_seconds=2, max_output_bytes=4)
    assert result.returncode == 0
    assert result.output_truncated is True


def test_cap_text_output_preserves_marker() -> None:
    assert "truncated" in cap_text_output("abcdef", 5)


def test_platform_profile_and_python_guard_are_structured() -> None:
    profile = detect_platform_profile()
    compatibility = current_python_gui_compatibility()
    assert profile.cpu_count >= 1
    assert compatibility.version


def test_shutdown_coordinator_closes_db(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    result = AppShutdownCoordinator(db=db).request_shutdown(source="test")
    assert result.graceful is True
    assert "db_closed" in result.steps


def test_scheduler_shutdown_cancels_cooperative_worker_and_rejects_new_work() -> None:
    scheduler = WorkScheduler(BALANCED_BUDGET)
    started = threading.Event()

    def cooperative(token):
        started.set()
        while not token.cancelled:
            time.sleep(0.01)

    scheduler.schedule(ScheduledTask(task_type="cooperative", subsystem="test", callable=cooperative))
    assert started.wait(1)
    outcome = scheduler.shutdown(cancel=True, timeout_seconds=1)
    rejected = scheduler.schedule(ScheduledTask(task_type="late", subsystem="test", callable=lambda _token: None))

    assert outcome["still_running"] == 0
    assert rejected.status == "cancelled"
    assert rejected.error == "scheduler is shutting down"


def test_scheduler_prunes_completed_task_history() -> None:
    scheduler = WorkScheduler(BALANCED_BUDGET, max_task_history=50)
    try:
        for index in range(80):
            scheduler.schedule(ScheduledTask(task_type=str(index), subsystem="test", callable=lambda _token: None))
        deadline = time.time() + 2
        while scheduler.snapshot()["running"] and time.time() < deadline:
            time.sleep(0.01)
        assert len(scheduler.snapshot()["tasks"]) <= 50
    finally:
        scheduler.shutdown(cancel=True)


def test_shutdown_coordinator_passes_scheduler_and_is_idempotent() -> None:
    class Scheduler:
        def __init__(self):
            self.calls = []

        def shutdown(self, **kwargs):
            self.calls.append(kwargs)
            return {"cancelled": 1, "completed": 1, "still_running": 0}

    scheduler = Scheduler()
    coordinator = AppShutdownCoordinator(scheduler=scheduler)
    first = coordinator.request_shutdown(source="test")
    second = coordinator.request_shutdown(source="again")

    assert scheduler.calls == [{"cancel": True, "timeout_seconds": 2.0}]
    assert any(step.startswith("scheduler_shutdown:") for step in first.steps)
    assert second.steps == ["already_shutting_down"]
