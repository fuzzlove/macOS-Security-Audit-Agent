from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from mac_audit_agent.compat.enum import StrEnum


class ResourceProfile(StrEnum):
    LOW_RESOURCE = "low_resource"
    BALANCED = "balanced"
    THOROUGH = "thorough"


@dataclass(frozen=True)
class ResourceBudget:
    profile: str
    max_cpu_percent_target: int
    max_memory_mb_soft: int
    max_memory_mb_hard: int
    max_concurrent_tasks: int
    max_subprocesses: int
    max_api_requests_per_minute: int
    api_timeout_seconds: int
    scan_timeout_seconds: int
    export_timeout_seconds: int
    refresh_min_interval_seconds: int
    low_power_mode_behavior: str
    battery_mode_behavior: str
    heavy_refresh_requires_user_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


LOW_RESOURCE_BUDGET = ResourceBudget(
    profile=ResourceProfile.LOW_RESOURCE.value,
    max_cpu_percent_target=35,
    max_memory_mb_soft=512,
    max_memory_mb_hard=1024,
    max_concurrent_tasks=1,
    max_subprocesses=1,
    max_api_requests_per_minute=10,
    api_timeout_seconds=10,
    scan_timeout_seconds=60,
    export_timeout_seconds=120,
    refresh_min_interval_seconds=3600,
    low_power_mode_behavior="defer_heavy_work",
    battery_mode_behavior="manual_heavy_refresh_only",
    heavy_refresh_requires_user_action=True,
)

BALANCED_BUDGET = ResourceBudget(
    profile=ResourceProfile.BALANCED.value,
    max_cpu_percent_target=55,
    max_memory_mb_soft=1024,
    max_memory_mb_hard=2048,
    max_concurrent_tasks=2,
    max_subprocesses=2,
    max_api_requests_per_minute=30,
    api_timeout_seconds=15,
    scan_timeout_seconds=180,
    export_timeout_seconds=240,
    refresh_min_interval_seconds=1800,
    low_power_mode_behavior="defer_background_heavy_work",
    battery_mode_behavior="stagger_background_refresh",
)

THOROUGH_BUDGET = ResourceBudget(
    profile=ResourceProfile.THOROUGH.value,
    max_cpu_percent_target=75,
    max_memory_mb_soft=2048,
    max_memory_mb_hard=4096,
    max_concurrent_tasks=3,
    max_subprocesses=3,
    max_api_requests_per_minute=60,
    api_timeout_seconds=20,
    scan_timeout_seconds=600,
    export_timeout_seconds=600,
    refresh_min_interval_seconds=900,
    low_power_mode_behavior="warn_before_heavy_work",
    battery_mode_behavior="allow_user_initiated_heavy_work",
)

# The public workstation build defaults to the smallest safe footprint. The
# existing balanced/thorough profiles remain available for contractor systems.
DEFAULT_RESOURCE_PROFILE = ResourceProfile.LOW_RESOURCE.value
_BUDGETS = {
    LOW_RESOURCE_BUDGET.profile: LOW_RESOURCE_BUDGET,
    BALANCED_BUDGET.profile: BALANCED_BUDGET,
    THOROUGH_BUDGET.profile: THOROUGH_BUDGET,
}


def budget_for_profile(profile: str | None) -> ResourceBudget:
    return _BUDGETS.get(str(profile or DEFAULT_RESOURCE_PROFILE), BALANCED_BUDGET)


def load_resource_profile_from_db(db: Any) -> str:
    try:
        return db.get_background_monitor_state("performance.resource_profile", DEFAULT_RESOURCE_PROFILE)
    except Exception:
        return DEFAULT_RESOURCE_PROFILE


def load_resource_budget(db: Any | None = None, profile: str | None = None) -> ResourceBudget:
    if profile:
        return budget_for_profile(profile)
    if db is not None:
        return budget_for_profile(load_resource_profile_from_db(db))
    return BALANCED_BUDGET


def persist_resource_profile(db: Any, profile: str) -> ResourceBudget:
    budget = budget_for_profile(profile)
    db.set_background_monitor_state("performance.resource_profile", budget.profile)
    db.set_background_monitor_state("performance.resource_budget_json", json.dumps(budget.to_dict(), sort_keys=True))
    return budget
