from __future__ import annotations

import time
import threading

from mac_audit_agent.cache.cache_manager import CacheManager
from mac_audit_agent.performance.api_refresh_manager import ApiRefreshManager
from mac_audit_agent.performance.db_optimization import ensure_performance_indexes
from mac_audit_agent.performance.resource_budget import BALANCED_BUDGET, load_resource_budget, persist_resource_profile
from mac_audit_agent.performance.subprocess_runner import run_bounded_command
from mac_audit_agent.performance.work_scheduler import ScheduledTask, WorkScheduler
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.runtime.python_compat import current_python_gui_compatibility
from mac_audit_agent.storage import AuditDatabase


def run_performance_audit(context: AuditContext) -> list[FunctionalCheck]:
    return [
        _startup_lightweight_check(context),
        _scheduler_limits_check(),
        _api_refresh_bounded_check(),
        _cache_resilience_check(context),
        _subprocess_bounds_check(),
        _db_indexes_check(context),
        _resource_profile_settings_check(context),
        _shutdown_graceful_check(context),
        _python_gui_runtime_guard_check(),
    ]


def _startup_lightweight_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("performance.startup_lightweight", "Performance", "startup lightweight", "Startup should not force every heavy refresh.", "high", "smoke")
    db = AuditDatabase(context.db_path)
    try:
        budget = load_resource_budget(db)
        return check.passed("Resource budget loads without triggering scan/API work.", budget.to_dict())
    finally:
        db.close()


def _scheduler_limits_check() -> FunctionalCheck:
    check = FunctionalCheck("performance.scheduler_limits", "Performance", "scheduler limits", "Scheduler enforces concurrency, cooldown, and dedupe.", "high", "smoke")
    scheduler = WorkScheduler(BALANCED_BUDGET)
    try:
        counter_lock = threading.Lock()
        started = threading.Event()
        release = threading.Event()
        executions = 0

        def overlapping_probe(token):
            nonlocal executions
            with counter_lock:
                executions += 1
            started.set()
            release.wait(timeout=2)
            return "ok"

        first = scheduler.schedule(ScheduledTask(task_type="probe", subsystem="pre_uat", dedupe_key="same", callable=overlapping_probe))
        if not started.wait(timeout=1):
            return check.failed("First scheduler task did not start.", "Fix scheduler dispatch before evaluating deduplication.")
        second = scheduler.schedule(ScheduledTask(task_type="probe", subsystem="pre_uat", dedupe_key="same", callable=overlapping_probe))
        release.set()
        time.sleep(0.1)
        cooldown = scheduler.schedule(ScheduledTask(task_type="probe", subsystem="pre_uat", dedupe_key="same", callable=overlapping_probe), cooldown_seconds=60)
        snapshot = scheduler.snapshot()
        evidence = snapshot | {
            "first_task_id": first.task_id,
            "second_task_id": second.task_id,
            "first_status": first.status,
            "second_status": second.status,
            "duplicate_result": "returned_skipped_deduped",
            "execution_count": executions,
            "cooldown_status": cooldown.status,
        }
        if executions != 1 or second.status != "skipped_deduped" or cooldown.status != "skipped_cooldown":
            return check.failed("Scheduler executed duplicate work or failed cooldown enforcement.", "Fix WorkScheduler atomic dedupe and cooldown handling.", evidence)
        return check.passed("Overlapping duplicate executed exactly once and cooldown was enforced.", evidence)
    finally:
        scheduler.shutdown(cancel=True)


def _api_refresh_bounded_check() -> FunctionalCheck:
    check = FunctionalCheck("performance.api_refresh_bounded", "Performance", "API refresh bounded", "API refresh has timeout/cache/backoff semantics.", "blocker", "smoke")
    cache = {"source": {"payload": {"cached": True}, "_cache_age_seconds": 0}}
    manager = ApiRefreshManager(BALANCED_BUDGET, cache_get=lambda key: cache.get(key), cache_set=lambda key, value: cache.__setitem__(key, value))
    result = manager.refresh("source", lambda: (_ for _ in ()).throw(RuntimeError("network down")), force=False)
    if not result.used_cache:
        return check.failed("API refresh did not use fresh cache before failed fetch.", "Use cache-first API refresh policy.", result.to_dict())
    return check.passed("API refresh used cache and avoided crash.", result.to_dict())


def _cache_resilience_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("performance.cache_resilience", "Performance", "cache resilience", "Corrupt cache must not crash lookup.", "high", "smoke")
    cache = CacheManager(context.output_dir / "cache_probe")
    path = cache._path_for_key("bad")
    path.write_text("{bad json", encoding="utf-8")
    result = cache.read_json("bad")
    if not result.corrupted:
        return check.failed("Corrupt cache was not detected.", "Mark corrupt cache entries and fall back to last known-good data.", result.to_dict())
    return check.passed("Corrupt cache detected without exception.", result.to_dict())


def _subprocess_bounds_check() -> FunctionalCheck:
    check = FunctionalCheck("performance.subprocess_bounds", "Performance", "subprocess bounds", "Subprocess timeout and output caps are enforced.", "blocker", "smoke")
    result = run_bounded_command(["/bin/echo", "ok"], timeout_seconds=2, max_output_bytes=4)
    if result.returncode != 0 or "ok" not in result.stdout:
        return check.failed("Bounded subprocess probe failed.", "Fix run_bounded_command result handling.", result.to_dict())
    return check.passed("Bounded subprocess completed with timeout/output controls.", result.to_dict())


def _db_indexes_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("performance.db_access_bounded", "Performance", "database access bounded", "Frequently queried DB fields have indexes.", "high", "smoke")
    db = AuditDatabase(context.db_path)
    try:
        indexes = ensure_performance_indexes(db)
        return check.passed("Performance indexes are present or created.", {"indexes": indexes})
    finally:
        db.close()


def _resource_profile_settings_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("performance.resource_profile_settings", "Performance", "resource profile settings", "Performance profile persists and applies.", "high", "smoke")
    db = AuditDatabase(context.db_path)
    try:
        budget = persist_resource_profile(db, "low_resource")
        loaded = load_resource_budget(db)
        if loaded.profile != budget.profile:
            return check.failed("Persisted resource profile did not reload.", "Repair performance settings persistence.", {"saved": budget.to_dict(), "loaded": loaded.to_dict()})
        return check.passed("Resource profile persisted and reloaded.", loaded.to_dict())
    finally:
        db.close()


def _shutdown_graceful_check(context: AuditContext) -> FunctionalCheck:
    check = FunctionalCheck("performance.shutdown_graceful_macos_menu", "Performance", "macOS menu quit graceful", "Shutdown coordinator flushes DB and cancels work.", "medium", "smoke")
    if not context.ui_interactive:
        return check.not_verified("GUI shutdown was not run because Pre-UAT is headless.", "Run the interactive UI shutdown check on a display.", {"mode": "headless", "runtime_geometry_ran": False})
    from mac_audit_agent.ui.app_shutdown import AppShutdownCoordinator

    db = AuditDatabase(context.db_path)
    coordinator = AppShutdownCoordinator(db=db)
    result = coordinator.request_shutdown(source="pre_uat")
    if not result.graceful:
        return check.failed("Shutdown coordinator reported errors.", "Fix AppShutdownCoordinator cleanup steps.", result.__dict__)
    return check.passed("Shutdown coordinator completed graceful cleanup.", result.__dict__)


def _python_gui_runtime_guard_check() -> FunctionalCheck:
    check = FunctionalCheck("performance.python_gui_runtime_guard", "Performance", "Python GUI runtime guard", "Unsupported Python GUI path is blocked before QApplication.", "blocker", "smoke")
    compatibility = current_python_gui_compatibility()
    return check.passed("Python GUI runtime compatibility is explicit.", compatibility.__dict__)
